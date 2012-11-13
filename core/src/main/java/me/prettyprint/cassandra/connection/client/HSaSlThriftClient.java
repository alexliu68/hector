package me.prettyprint.cassandra.connection.client;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.RealmChoiceCallback;
import javax.security.sasl.Sasl;

import me.prettyprint.cassandra.connection.security.KerberosHelper;
import me.prettyprint.cassandra.service.CassandraHost;
import me.prettyprint.cassandra.service.SystemProperties;
import me.prettyprint.hector.api.exceptions.HInvalidRequestException;
import me.prettyprint.hector.api.exceptions.HectorTransportException;

import org.apache.cassandra.thrift.Cassandra;
import org.apache.cassandra.thrift.InvalidRequestException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.thrift.TException;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.transport.TFramedTransport;
import org.apache.thrift.transport.TSSLTransportFactory;
import org.apache.thrift.transport.TSaslClientTransport;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportException;
import org.apache.thrift.transport.TSSLTransportFactory.TSSLTransportParameters;
import org.ietf.jgss.GSSContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.security.auth.module.Krb5LoginModule;

public class HSaSlThriftClient extends HThriftClient implements HClient {

    private static Logger log = LoggerFactory.getLogger(HSaSlThriftClient.class);
    
    private String servicePrincipalName;
    private TSSLTransportParameters params;

    /**
     * Constructor
     * @param cassandraHost
     * @param servicePrincipalName, name/_HOST@DOMAIN,  e.g. mapred/bdplab0.datastax.com@EXAMPLE.COM
     */
    public HSaSlThriftClient(CassandraHost cassandraHost, String servicePrincipalName) {
      super(cassandraHost);
      this.servicePrincipalName = servicePrincipalName;
    }

    /**
     * Constructor
     * @param cassandraHost
     * @param servicePrincipalName, name/_HOST@DOMAIN,  e.g. mapred/bdplab0.datastax.com@EXAMPLE.COM
     * @param params
     */
    public HSaSlThriftClient(CassandraHost cassandraHost, String servicePrincipalName, TSSLTransportParameters params) {
      super(cassandraHost);
      this.servicePrincipalName = servicePrincipalName;
      this.params = params;
    }
    
    /**
     * {@inheritDoc}
     */
    public HSaSlThriftClient open() {
      if ( isOpen() ) {
        throw new IllegalStateException("Open called on already open SASL connection. You should not have gotten here.");
      }
      if ( log.isDebugEnabled() ) {
        log.debug("Creating a new SASL thrift connection to {}", cassandraHost);
      }
      
      TSocket socket;    
      try {
          socket = params == null ? 
                                  new TSocket(cassandraHost.getHost(), cassandraHost.getPort(), timeout)
                                  : TSSLTransportFactory.getClientSocket(cassandraHost.getHost(), cassandraHost.getPort(), timeout, params);
      } catch (TTransportException e) {
          throw new HectorTransportException("Could not get client socket: ", e);
      }
              
      if ( cassandraHost.getUseSocketKeepalive() ) {
        try {
          socket.getSocket().setKeepAlive(true);
        } catch (SocketException se) {
          throw new HectorTransportException("Could not set SO_KEEPALIVE on socket: ", se);
        }
      }

      if (cassandraHost.getUseThriftFramedTransport()) {
        transport = new TFramedTransport(socket);
      } else {
        transport = socket;
      }

      boolean success = false;
      try {
          openKerberosTransport(transport, servicePrincipalName);
          success = true;
      } catch (LoginException e) {
          log.error("kerberos login failed.", e);
      } catch (TTransportException e1) {
          log.error("Failed to open kerberos transport.", e1);
      }

      if (!success) {
        close();
        throw new HectorTransportException("Kerberos context couldn't be established with client.");
      }

      return this;
    }
    
    public static TTransport openKerberosTransport(TTransport socket, String kerberosServicePrincipal) throws LoginException, TTransportException {
        try {
            log.debug("Opening kerberos transport...");
            Subject kerberosTicket = new Subject();
            LoginContext login = new LoginContext("Client", kerberosTicket, null, new KerberosUserConfiguration());
            login.login();

            String names[] = kerberosServicePrincipal.split("[/@]");

            if (names.length != 3) {
                throw new IOException("Kerberos principal name does NOT have the expected hostname part: "+ kerberosServicePrincipal);
            }

            final TSaslClientTransport transport = new TSaslClientTransport(
                    "GSSAPI",
                    null,
                    names[0], names[1],
                    SASL_PROPS, null,
                    socket);

            Subject.doAs(kerberosTicket, new PrivilegedAction<Void>() {

                @Override
                public Void run() {
                    try {
                        transport.open();
                    } catch (TTransportException e) {
                        throw new RuntimeException("Unable to connect to dse server:", e);
                    }

                    return null;
                }
            });

            log.debug("Kerberos transport opened successfully");
            return new TFramedTransport(transport);
        } catch (IOException e) {
            throw new TTransportException("Failed to open secure transport using KERBEROS", e);
        }
    }


    public static class KerberosUserConfiguration extends javax.security.auth.login.Configuration {

        private static final Map<String, String> USER_KERBEROS_OPTIONS =
                new HashMap<String, String>();
        static {
            USER_KERBEROS_OPTIONS.put("doNotPrompt", "true");
            USER_KERBEROS_OPTIONS.put("useTicketCache", "true");
            USER_KERBEROS_OPTIONS.put("renewTGT", "true");
            String ticketCache = System.getenv("KRB5CCNAME");
            if (ticketCache != null)
                USER_KERBEROS_OPTIONS.put("ticketCache", ticketCache);
        }
        
        private static final AppConfigurationEntry USER_KERBEROS_LOGIN =
                new AppConfigurationEntry(Krb5LoginModule.class.getName(),
                        AppConfigurationEntry.LoginModuleControlFlag.OPTIONAL,
                        USER_KERBEROS_OPTIONS);

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String arg0) {
            return new AppConfigurationEntry[] { USER_KERBEROS_LOGIN };
        }
    }

    public static final Map<String, String> SASL_PROPS = new TreeMap<String, String>() {{
        SASL_PROPS.put(Sasl.QOP, "auth");
        SASL_PROPS.put(Sasl.SERVER_AUTH, "true");
    }};
}
