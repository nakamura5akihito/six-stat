package jp.go.aist.six.stat.tool;

import java.io.File;
import java.io.PrintStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Formatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import jp.go.aist.six.stat.model.OvalRepositoryProvider;
import jp.go.aist.six.stat.model.Table;
import jp.go.aist.six.vuln.model.scap.cvss.BaseMetricsType;
import jp.go.aist.six.vuln.model.scap.cvss.CvssImpactType;
import jp.go.aist.six.vuln.model.scap.vulnerability.VulnerabilityType;



/**
 */
public class StatReporter
{

    public static final int  PERIOD_BEGIN = 1999;
    public static final int  PERIOD_END = 2013;



    public static void main(
                    final String[] args
                    )
    throws Exception
    {
        StatReporter  reporter = new StatReporter();
        reporter.reportNumberOfEntries( PERIOD_BEGIN, PERIOD_END );
        reporter.reportNvdCveByCvss( PERIOD_BEGIN, PERIOD_END );
        reporter.reportOvalCoveredOfCve( PERIOD_BEGIN, PERIOD_END );
    }


    private static final  String  _OUTPUT_DIR_ = "/Users/akihito/tmp/six-stat";



    private final File  _output_dir;
    protected NvdAnalyzer    _nvd_analyzer;
    protected OvalAnalyzer  _oval_analyzer;


    /**
     */
    public StatReporter()
    {
        _output_dir = _mkOutputDirs();

        _nvd_analyzer = new NvdAnalyzer();
       _oval_analyzer = new OvalAnalyzer();
    }





    /**
     * Report: OVAL Coverage of CVE
     *
     * { "Year", "NVD/CVE (except Rejected)", "OVAL (Mitre except Deprecated)", "Coverage", "CVE covered by OVAL" }
     * 1999, nvd-cve_count_1999, oval_count_1999, coverage_1999, [cve-list1]
     * 2000, nvd-cve_count_2000, oval_count_2000, coverage_2000, [cve-list2]
     * ...
     */
    public void reportOvalCoveredOfCve(
                    final int year_begin,
                    final int year_end
                    )
    throws Exception
    {
        String  title = "***** OVAL: Coverage of CVE *****";
        _println( System.out, title );

        final String  filename_prefix = "oval_coverage-of-cve_";
        String[]  table_header = new String[] {
                        "Year",
                        "NVD/CVE (except Rejected)",
                        "OVAL/CVE (Mitre except Deprecated)",
                        "Coverage",
                        "CVE covered by OVAL"
                        };
        Table  table = new Table( table_header );

        Map<Integer,Long>  nvd_cve_counts = getNumberOfNvdCveEntriesExceptRejectedByYear( year_begin, year_end );
        for (int  year = year_begin; year <= year_end; year++) {
            Set<String>  oval_cve_set =
                            _oval_analyzer.findCveIdFromVulnDefExceptDeprecatedByCveYear( year, OvalRepositoryProvider.MITRE );

            long  nvd_cve_count = nvd_cve_counts.get( year );
            int  oval_cve_count = oval_cve_set.size();
            Formatter  formatter = new Formatter();
            formatter.format( "%.3f", ((float)oval_cve_count / (float)nvd_cve_count) );

            table.addRow( new Object[] {
                            year,
                            nvd_cve_count,
                            oval_cve_count,
                            formatter.out(),
                            oval_cve_set
                            });

            formatter.close();
        }

        //output//
        _outputReport( table, filename_prefix + year_begin + "-" + year_end );
    }



    /**
     * NVD: CVE by CVSS.
     *
     * Unknown: Entries which contains no CVSS property.
     * REJECT:  Entries which are rejected.
     *          Note: Now, rejected entries are filtered in the query processing.
     *                So, the count must be zero in every year.
     *
     * { "Year", "NVD/CVE (except Rejected),
     * 　"High (7.0--10.0)", "Medium (4.0--6.9)", "Low (0.0--3.9)", "Unknown (no CVSS)"" }
     */
    public void reportNvdCveByCvss(
                    final int year_begin,
                    final int year_end
                    )
    throws Exception
    {
        String  title = "***** NVD: CVE by CVSS score *****";
        _println( System.out, title );

        final String  filename_prefix = "nvd_cve-by-cvss_";
        final String[]  table_header = new String[] {
                        "Year",
                        "High (7.0--10.0)",
                        "Medium (4.0--6.9)",
                        "Low (0.0--3.9)",
                        "Unknown (no CVSS except Rejected)",
                        "NVD/CVE (H+M+L+U)"
                        };

        Table  table = new Table( table_header );
        for (int  year = year_begin; year <= year_end; year++) {
            int  count_low = 0;
            int  count_medium = 0;
            int  count_high = 0;
            int  count_unknown = 0;

            List<VulnerabilityType>  vuln_list =  _nvd_analyzer.findVulnExceptRejectedByCveYear( year );
            for (VulnerabilityType  vuln : vuln_list) {
                Double  score = null;
                CvssImpactType  cvss = vuln.getCvss();
                if (cvss != null) {
                    BaseMetricsType  base = cvss.getBaseMetrics();
                    if (base != null) {
                        score = base.getScore();
                    }
                }

                if (score == null) {
                    count_unknown++;
                    _println( System.out, "CVSS N/A: " + vuln.getId() );
                } else {
                    if (score < 4.0f) {
                        count_low++;
                    } else if (score < 7.0f) {
                        count_medium++;
                    } else {
                        count_high++;
                    }
                }
            }

            table.addRow( new Object[] {
                            year,
                            count_low,
                            count_medium,
                            count_high,
                            count_unknown,
                            count_low + count_medium + count_high + count_unknown,
                            });
        }

        //output//
        _outputReport( table, filename_prefix + year_begin + "-" + year_end );
    }



    /**
     * Report:
     * @param year_begin
     * @param year_end
     */
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
                        "OVAL (Mitre V Def, except Deprected)",
                        "OVAL (Red Hat P Def, except Deprecated)"
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
     * 1999, 1234
     * 2000, 5678
     * ...
     */
    public Map<Integer,Long> getNumberOfNvdCveEntriesExceptRejectedByYear(
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
    //  file I/O
    ///////////////////////////////////////////////////////////////////////

    /**
     * Output CSV.
     */
    protected void _outputReport(
                    final Table table,
                    final String filename
                    )
    throws Exception
    {
        File  file = _createOutputFile( filename + ".csv" );
        _println( System.out, "output file: " + file.getName() );
        table.saveToCsv( file );
    }



    private static final String  _DATE_FORMAT_ = "yyyy-MM-dd'T'HHmmss.SSS";

    private File _mkOutputDirs()
    {
        SimpleDateFormat  formatter = new SimpleDateFormat( _DATE_FORMAT_ );
        String  dirname = formatter.format( new Date() );
        File  dir = new File( _OUTPUT_DIR_, dirname );
        dir.mkdirs();
        _println( System.out, "output dir: " + dir.getAbsolutePath() );

        return dir;
    }


    protected File _getOutputDir()
    {
        return _output_dir;
    }



    protected File _createOutputFile(
                    final String filename
                    )
    {
        File  file = new File( _getOutputDir(), filename );
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
