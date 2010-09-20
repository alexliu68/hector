package me.prettyprint.cassandra.model;

import java.util.List;

import me.prettyprint.cassandra.utils.Assert;
import me.prettyprint.hector.api.beans.ColumnSlice;
import me.prettyprint.hector.api.beans.Row;

import org.apache.cassandra.thrift.Column;

/**
 * A Row is a touple consisting of a Key and a Column Slice.
 *
 * A Row may be used to hold the returned value from queries such as get_range_slices.
 *
 * @author Ran Tavory
 *
 * @param <N> Column name type
 * @param <V> Column value type
 *
 */
public final class RowImpl<N,V> implements Row<N, V> {

  private final String rowKey;
  private final ColumnSlice<N, V> columnSlice;

  /*package*/ RowImpl(String rowKey, List<Column> columns, Serializer<N> nameSerializer,
      Serializer<V> valueSerializer) {
    Assert.noneNull(rowKey, columns, nameSerializer, valueSerializer);
    this.rowKey = rowKey;
    columnSlice = new ColumnSliceImpl<N,V>(columns, nameSerializer, valueSerializer);
  }

  @Override
  public String getKey() {
    return rowKey;
  }

  @Override
  public ColumnSlice<N, V> getColumnSlice() {
    return columnSlice;
  }

  @Override
  public String toString() {
    return "Row(" + rowKey + "," + columnSlice + ")";
  }
}