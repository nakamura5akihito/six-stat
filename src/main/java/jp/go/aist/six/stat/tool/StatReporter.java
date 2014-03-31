package jp.go.aist.six.stat.tool;

import java.io.File;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import jp.go.aist.six.stat.model.OvalRepositoryProvider;
import jp.go.aist.six.stat.model.Table;



/**
 */
public class StatReporter
{

    public static final int  PERIOD_BEGIN = 2004;
    public static final int  PERIOD_END = 2013;



    public static void main(
                    final String[] args
                    )
    throws Exception
    {
        StatReporter  reporter = new StatReporter();
        reporter.reportNumberOfEntries( PERIOD_BEGIN, PERIOD_END );
    }





    protected NvdAnalyzer    _nvd_analyzer;
    protected OvalAnalyzer  _oval_analyzer;


    /**
     */
    public StatReporter()
    {
        _mkdirs();

        _nvd_analyzer = new NvdAnalyzer();
       _oval_analyzer = new OvalAnalyzer();
    }



    public void reportNumberOfEntries(
                    final int year_begin,
                    final int year_end
                    )
    throws Exception
    {
        String  title = "***** NVD and OVAL: Number of Entries *****";
        _println( System.out, title );

        final String  filename_prefix = "nvd-oval_entries_";
        String[]  table_header = new String[] {
                        "Year",
                        "NVD/CVE (except Rejected)",
                        "OVAL (Mitre except Deprected)",
                        "OVAL (Red Hat except Deprecated)"
                        };

        //analysis//
        Table  table = new Table( table_header );
        for (int  year = year_begin; year <= year_end; year++) {
            long     cve_count =  _nvd_analyzer.countVulnExceptRejectedByCveYear( year );
            long   mitre_count = _oval_analyzer.countOvalVulnDefExceptDeprecatedByCveYear( year, OvalRepositoryProvider.MITRE );
            long  redhat_count = _oval_analyzer.countOvalVulnDefExceptDeprecatedByCveYear( year, OvalRepositoryProvider.REDHAT );

            table.addRow( new Object[] {
                            year,
                            cve_count,
                            mitre_count,
                            redhat_count
            });
        }

        //output//
        _outputReport( table, filename_prefix + year_begin + "-" + year_end );
    }


    ////////////////////////////////////////////////////////////////////////////

    private final Map<Integer,Long>  _numberOfNvdCveEntriesByYear = new HashMap<Integer,Long>();


    /**
     * Number of NVD/CVE Entries.
     *
     * 1999, count1999
     * 2000, count2000
     * ...
     */
    public Map<Integer,Long> getNumberOfNvdCveEntriesByYear(
                    final int  year_begin,
                    final int  year_end
                    )
    throws Exception
    {
        for (int  year = year_begin; year <= year_end; year++) {
            if (! _numberOfNvdCveEntriesByYear.containsKey( year )) {
                long  count =  _nvd_analyzer.countVulnExceptRejectedByCveYear( year );
                _numberOfNvdCveEntriesByYear.put( year, count );
            }
        }

        return _numberOfNvdCveEntriesByYear;
    }





//    /**
//     * Picks up the specified year CVE IDs from the given definitions.
//     */
//    private SortedSet<String> _buildYearCveList(
//                    final Collection<DefinitionType> def_list,
//                    final int year
//                    )
//    {
//        SortedSet<String>  cve_set = new TreeSet<String>();
//
//        String  cve_prefix = "CVE-";
//        if (year != 0) {
//            cve_prefix = cve_prefix + String.valueOf( year );
//        }
//
//        for (DefinitionType  def : def_list) {
//            if (DefinitionType.deprecated( def )) {
//                continue;
//            }
//
//            Collection<ReferenceType>  ref_list = def.getMetadata().getReference();
//            if (ref_list != null) {
//                for (ReferenceType  ref : ref_list) {
//                    if ("CVE".equals( ref.getSource() )) {
//                        String  cve_id = ref.getRefId();
//                        if (cve_id.startsWith( cve_prefix )) {
//                            cve_set.add( cve_id );
//                        }
//                    }
//                }
//            }
//        }
//
//        return cve_set;
//    }


    ///////////////////////////////////////////////////////////////////////
    //  name unification
    ///////////////////////////////////////////////////////////////////////

    /**
     *  OVAL product
     */
    private static final Map<String,String> _createOvalProductNameMapping()
    {
        Map<String,String>  map = new HashMap<String,String>();

        String  ie = "microsoft ie";
        map.put( "microsoft internet explorer",                     ie );
        map.put( "microsoft internet explorer 10",                  ie );
        map.put( "microsoft internet explorer 5.01",                ie );
        map.put( "microsoft internet explorer 6",                   ie );
        map.put( "microsoft internet explorer 7",                   ie );
        map.put( "microsoft internet explorer 8",                   ie );
        map.put( "microsoft internet explorer 9",                   ie );
        map.put( "internet explorer is installed on the system.",   ie );

        String  java = "sun-oracle jdk-jre";
        map.put( "java development kit",        java );
        map.put( "java runtime environment",    java );
        map.put( "oracle java se",              java );
        map.put( "java development kit",        java );
        map.put( "java runtime environment",    java );

        String  office = "microsoft office";
        map.put( "microsoft office xp",             office );
        map.put( "microsoft office xp sp2",         office );
        map.put( "microsoft office xp sp3",         office );
        map.put( "microsoft office 2000",           office );
        map.put( "microsoft office 2000 sp3",       office );
        map.put( "microsoft office 2002",           office );
        map.put( "microsoft office 2003",           office );
        map.put( "microsoft office 2007",           office );
        map.put( "microsoft office 2008",           office );
        map.put( "microsoft office 2008 for mac",   office );
        map.put( "microsoft office 2010",           office );
        map.put( "microsoft office 2011 for mac",   office );

        String  excel = "microsoft excel";
        map.put( "microsoft excel 97",             excel );
        map.put( "microsoft excel 2000",           excel );
        map.put( "microsoft excel 2002",           excel );
        map.put( "microsoft excel 2003",           excel );
        map.put( "microsoft excel 2007",           excel );
        map.put( "microsoft excel 2010",           excel );

        String  adobe_reader = "adobe reader";
        map.put( "adobe acrobat reader",    adobe_reader );

        String  flash = "adobe flash player";
        map.put( "flash player",            flash );

        return map;
    }

    private static final Map<String,String>  _OVAL_PRODUCT_NAME_MAP_ = _createOvalProductNameMapping();


    /**
     */
    public static final String ovalUnifiedProductName(
                    final String name
                    )
    {
        String  product_name = name.toLowerCase();
        //NOTE: there may be upper case name, lower case name, and mixture name
        // e.g. "Adobe AIR" and "Adobe Air"

        String  unified_name = _OVAL_PRODUCT_NAME_MAP_.get( product_name );

        return (unified_name == null ? product_name : unified_name);
    }





    ///////////////////////////////////////////////////////////////////////
    //  I/O
    ///////////////////////////////////////////////////////////////////////

    private static final  String  _OUTPUT_DIR_ = "analysis";


    /**
     * Output CSV.
     */
    protected void _outputReport(
                    final Table table,
                    final String filename
                    )
    throws Exception
    {
        File  file = _createOutputFile( filename + "_" + System.currentTimeMillis() + ".csv" );
        _println( System.out, "output file: " + file.getName() );
        table.saveToCsv( file );
    }



    private static void _mkdirs()
    {
        File  dir = new File( _OUTPUT_DIR_ );
        dir.mkdirs();
    }


    protected static File _createOutputFile(
                    final String filename
                    )
    {
        File  file = new File( _OUTPUT_DIR_, filename );
        return file;
    }



    /**
     */
    protected static void _println(
                    final PrintStream output,
                    final String txt
                    )
    {
        output.println( txt );
        output.flush();
    }

}
//
