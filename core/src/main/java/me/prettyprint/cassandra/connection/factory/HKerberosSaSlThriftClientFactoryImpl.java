/**
 * Client Factory that provides Secure sockets using Kerberos as authentication
 * SASL mechanism.
 * 
 * It expects few system properties to be set up:
 * <ul>
 * <li><code>kerberos.service.principal.name</code> Kerberos Service principal name without the domain. Default: "cassandra".
 * 
 * <li><code>ssl.truststore</code> File path for trust store
 * <li><code>ssl.truststore.password</code> Password for trust store
 * <li><code>ssl.protocol</code> SSL protocol, default SSL
 * <li><code>ssl.store.type</code> Store type, default JKS
 * <li><code>ssl.cipher.suites</code> Cipher suites
 * </ul>
 * <p>
 * 
 * 
 * @see HSaslThriftClient
 * 
 */
package me.prettyprint.cassandra.connection.factory;

import org.apache.thrift.transport.TSSLTransportFactory.TSSLTransportParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import me.prettyprint.cassandra.connection.client.HClient;
import me.prettyprint.cassandra.connection.client.HKerberosThriftClient;
import me.prettyprint.cassandra.connection.client.HSaSlThriftClient;
import me.prettyprint.cassandra.connection.security.SSLHelper;
import me.prettyprint.cassandra.service.CassandraHost;

public class HKerberosSaSlThriftClientFactoryImpl implements HClientFactory {


    private static final Logger log = LoggerFactory.getLogger(HKerberosSecuredThriftClientFactoryImpl.class);

    public static final String JAAS_CONFIG = "jaas.conf";
    public static final String KRB5_CONFIG = "krb5.conf";

    private String krbServicePrincipalName;
    private TSSLTransportParameters params;

    public HKerberosSaSlThriftClientFactoryImpl() {

      params = SSLHelper.getTSSLTransportParameters();
      if (params != null) {
        log.info("SSL Properties:");
        log.info("  ssl.truststore = {}", System.getProperty("ssl.truststore"));
        log.info("  ssl.protocol = {}", System.getProperty("ssl.protocol"));
        log.info("  ssl.store.type = {}", System.getProperty("ssl.store.type"));
        log.info("  ssl.cipher.suites = {}", System.getProperty("ssl.cipher.suites")); 
      }
      
      krbServicePrincipalName = System.getProperty("kerberos.service.principal.name");
      log.info("kerberos Properties:");
      log.info("  kerberos.service.principal.name = {}", krbServicePrincipalName); 
    }

    /**
     * {@inheritDoc}
     */
    public HClient createClient(CassandraHost ch) {
      if (log.isDebugEnabled()) {
        log.debug("Creation of new client");
      }
      
      return params == null ?
                 new HSaSlThriftClient(ch, krbServicePrincipalName)
                  : new HSaSlThriftClient(ch, krbServicePrincipalName, params);
    }
}
