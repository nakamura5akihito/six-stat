package jp.go.aist.six.stat.model;

import java.io.File;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;



/**
 */
public class Table
    implements Iterable<Object[]>
{

    private String[]  _header = new String[0];
    private final List<Object[]>  _rows = new ArrayList<Object[]>();

//    private final SortedMap<Object,List<?>>  _rows = new TreeMap<Object,List<?>>();


    /**
     */
    public Table()
    {
    }


    public Table(
                    final String[] header
                    )
    {
        setHeader( header );
    }



    /**
     */
    public void setHeader(
                    final List<String> header
                    )
    {
        setHeader( header.toArray( new String[0] ) );
    }


    public void setHeader(
                    final String[] header
                    )
    {
        _header = header;
    }


    public String[] getHeader()
    {
        return _header;
    }


//    public int columns()
//    {
//        return _header.size();
//    }


    public int columns()
    {
        return _header.length;
    }



    /**
     */
    public void addRow(
                    final List<?> values
                    )
    {
        addRow( values.toArray() );
    }


    public void addRow(
                    final Object[] values
                    )
    {
        _rows.add( values );
    }



    public Iterator<Object[]> iterator()
    {
        return _rows.iterator();
    }



    public int size()
    {
        return _rows.size();
    }



    ///////////////////////////////////////////////////////////////////////
    //  output functions
    ///////////////////////////////////////////////////////////////////////

    /**
     */
    public void saveToCsv(
                    final File file
                    )
    throws Exception
    {
        PrintStream  output_file = new PrintStream( file );

        _println( output_file, _toCsvString( getHeader() ) );
        for (Object[]  row : this) {
            _println( output_file, _toCsvString( row ) );
        }
    }



    private static String _toCsvString(
                    final Object[] row
                    )
    {
        StringBuffer  s = new StringBuffer();
        final int  length = row.length;

        for (int  i = 0; i < length; i++) {
            if (i != 0) {
                s.append( "," );
            }

            s.append( row[i] );
        }

        return s.toString();
    }



    /**
     */
    private static void _println(
                    final PrintStream output,
                    final String txt
                    )
    {
        output.println( txt );
        output.flush();
    }

}
//
