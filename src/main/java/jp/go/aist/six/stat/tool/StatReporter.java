package jp.go.aist.six.stat.tool;

import java.io.File;
import java.io.PrintStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.EnumMap;
import java.util.Formatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import jp.go.aist.six.oval.model.common.ClassEnumeration;
import jp.go.aist.six.oval.model.common.FamilyEnumeration;
import jp.go.aist.six.oval.model.definitions.AffectedType;
import jp.go.aist.six.oval.model.definitions.DefinitionType;
import jp.go.aist.six.oval.model.definitions.ReferenceType;
import jp.go.aist.six.stat.model.OvalRepositoryProvider;
import jp.go.aist.six.stat.model.Table;
import jp.go.aist.six.stat.model.VulnerabilitySummary;
import jp.go.aist.six.vuln.model.scap.cvss.BaseMetricsType;
import jp.go.aist.six.vuln.model.scap.cvss.CvssImpactType;
import jp.go.aist.six.vuln.model.scap.vulnerability.CweReferenceType;
import jp.go.aist.six.vuln.model.scap.vulnerability.VulnerabilityType;
import jp.go.aist.six.vuln.model.scap.vulnerability.VulnerableSoftwareType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



/**
 */
public class StatReporter
{

    /**
     * Logger.
     */
    private static final Logger  _LOG_ = LoggerFactory.getLogger( StatReporter.class );



    public static final int  PERIOD_BEGIN = 1999;
    public static final int  PERIOD_END = 2013;



    public static void main(
                    final String[] args
                    )
    throws Exception
    {
        StatReporter  reporter = new StatReporter();
//        reporter.statNumberOfEntries( PERIOD_BEGIN, PERIOD_END );
//        reporter.statNvdCveByCvss( PERIOD_BEGIN, PERIOD_END );
//        reporter.statNvdCveByCwe( PERIOD_BEGIN, PERIOD_END );
//        reporter.statNvdCveByProduct( PERIOD_BEGIN, PERIOD_END );
//        reporter.statOvalCoverageOfCve( PERIOD_BEGIN, PERIOD_END );
        reporter.statOvalVulnDefByFamily( PERIOD_BEGIN, PERIOD_END );

//        reporter.reportNumberOfEntries( PERIOD_BEGIN, PERIOD_END );   //A.1, A.2
//        reporter.reportNvdCveByCvss( PERIOD_BEGIN, PERIOD_END );      //B.1
//        reporter.reportNvdCveByCwe( PERIOD_BEGIN, PERIOD_END );       //B.2
//        reporter.reportNvdCveByProduct( PERIOD_BEGIN, PERIOD_END );   //C.1
//        reporter.reportOvalCoverageOfCve( PERIOD_BEGIN, PERIOD_END );    //D.1
//      reporter.reportOvalVulnDefByFamily( PERIOD_BEGIN, PERIOD_END );   //D.2
    }


    private static final  String  _OUTPUT_DIR_ = "/Users/akihito/tmp/six-stat";



    private final File  _output_dir;
    protected NvdAnalyzer    _nvd_analyzer;
    protected OvalAnalyzer  _oval_analyzer;


    /**
     */
    public StatReporter()
    throws Exception
    {
        _output_dir = _mkOutputDirs();

        _nvd_analyzer = new NvdAnalyzer();
        _oval_analyzer = new OvalAnalyzer();

        getNumberOfNvdCveEntries( PERIOD_BEGIN, PERIOD_END );
    }



    private final Map<Integer,Long>  _number_of_nvdcve_entries = new HashMap<Integer,Long>();


    /**
     * Number of NVD/CVE Entries.
     *
     * 1999, 1234
     * 2000, 5678
     * ...
     */
    public Map<Integer,Long> getNumberOfNvdCveEntries(
                    final int  year_begin,
                    final int  year_end
                    )
    throws Exception
    {
        for (int  cve_year = year_begin; cve_year <= year_end; cve_year++) {
            if (! _number_of_nvdcve_entries.containsKey( cve_year )) {
                long  count =  _nvd_analyzer.countVulnByCveYear( cve_year );
                _number_of_nvdcve_entries.put( cve_year, count );
            }
        }

        return _number_of_nvdcve_entries;
    }






    /**
     * NVD, OVAL: Number of Entries.
     */
    public void statNumberOfEntries(
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
                        "NVD/CVE",
                        "OVAL (Mitre V+P Def)",
                        "-OVAL (Mitre V Def)",
                        "-OVAL (Mitre P Def)",
                        "OVAL (Red Hat P Def)"
                        };

        Map<Integer,Long>  cve_counts = getNumberOfNvdCveEntries( year_begin, year_end );

        Table  table = new Table( table_header );
        for (int  cve_year = year_begin; cve_year <= year_end; cve_year++) {
            long       cve_count =  cve_counts.get( cve_year );
//            long       cve_count =  _nvd_analyzer.countVulnByCveYear( cve_year );
            long   mitre_v_count = _oval_analyzer.countDefByCveYear( cve_year, ClassEnumeration.VULNERABILITY, OvalRepositoryProvider.MITRE );
            long   mitre_p_count = _oval_analyzer.countDefByCveYear( cve_year, ClassEnumeration.PATCH, OvalRepositoryProvider.MITRE );
            long  redhat_p_count = _oval_analyzer.countDefByCveYear( cve_year, ClassEnumeration.PATCH, OvalRepositoryProvider.REDHAT );

            table.addRow( new Object[] {
                            cve_year,
                            cve_count,
                            mitre_v_count + mitre_p_count,
                            mitre_v_count,
                            mitre_p_count,
                            redhat_p_count
            });
        }

        //output//
        _outputReport( table, filename_prefix + year_begin + "-" + year_end );
    }



    /**
     * NVD: CVE by CVSS score.
     */
    public void statNvdCveByCvss(
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
                        "Unknown (CVSS N/A)",
                        "NVD/CVE (H+M+L+U)"
                        };

        Table  table = new Table( table_header );
        for (int  cve_year = year_begin; cve_year <= year_end; cve_year++) {
            int  count_low     = 0;
            int  count_medium  = 0;
            int  count_high    = 0;
            int  count_unknown = 0;

            List<VulnerabilityType>  vuln_list =  _nvd_analyzer.findVulnByCveYear( cve_year );
            for (VulnerabilityType  vuln : vuln_list) {
                Double  score = _getCvssBaseScore( vuln );
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
                            cve_year,
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



    private static final Double _getCvssBaseScore(
                    final VulnerabilityType vuln
                    )
    {
        Double  score = null;
        CvssImpactType  cvss = vuln.getCvss();
        if (cvss != null) {
            BaseMetricsType  base = cvss.getBaseMetrics();
            if (base != null) {
                score = base.getScore();
            }
        }

        return score;
    }



    /**
     * NVD: CVE by CWE.
     */
    public void statNvdCveByCwe(
                    final int year_begin,
                    final int year_end
                    )
    throws Exception
    {
        String  title = "***** NVD: CVE by CWE *****";
        _println( System.out, title );

        final String  filename_prefix = "nvd_cve-by-cwe_";
        final String[]  yearly_table_header = new String[] {
                        "CWE",
                        "NVD/CVE"
//                        ,"Avg CVSS"   //TODO:
                        };

        String  total_column_name = "Total NVD/CVE (" + year_begin + "--" + year_end + ")";
        final String[]  total_table_header_prefix = new String[] {
                        "CWE",
                        total_column_name,
//                        "1999", "2000", ..., "2012"
                        };
        List<String>  total_table_header = new ArrayList<String>( Arrays.asList( total_table_header_prefix ) );
        Map<String,Collection<String>>  total_cwe2cve_map = new TreeMap<String,Collection<String>>();
        //<CWE,{CVE}>


        Map<Integer,Map<String,Collection<String>>>  historical_cwe2cve_map = new TreeMap<Integer,Map<String,Collection<String>>>();
        //<year,Map<CWE,{CVE}>>

        for (int  cve_year = year_begin; cve_year <= year_end; cve_year++) {
            Map<String,Collection<String>>  yearly_cwe2cve_map = new TreeMap<String,Collection<String>>();
            //<CWE,{CVE}>

            List<VulnerabilityType>  year_vuln_list =  _nvd_analyzer.findVulnByCveYear( cve_year );
            for (VulnerabilityType  vuln : year_vuln_list) {
                _mapCwe( vuln, yearly_cwe2cve_map );
            }
            historical_cwe2cve_map.put( new Integer( cve_year ), yearly_cwe2cve_map );

            //{CWE, #CVE, [CVE list]}
            Table  yearly_table = _buildNvdCveByCweSimpleReport( yearly_table_header, yearly_cwe2cve_map );
            _outputReport( yearly_table, filename_prefix + cve_year );

            _meargeCwe2CveMap( yearly_cwe2cve_map, total_cwe2cve_map );
            total_table_header.add( String.valueOf( cve_year ) );
        }

        /* year, total */
        Table  total_table = _buildNvdCveByCweTotalReport(
                        total_table_header.toArray( new String[0] ), total_cwe2cve_map, historical_cwe2cve_map );
        _outputReport( total_table, filename_prefix + year_begin + "-" + year_end );
    }



    private void _mapCwe(
                    final VulnerabilityType vuln,
                    final Map<String,Collection<String>> cwe2cve_map
                    )
    {
        Collection<CweReferenceType>  cwe_list = vuln.getCwe();
        if (cwe_list == null  ||  cwe_list.size() == 0) {
            _println( System.out, "CWE unknown: " + vuln.getId() );
            _addCve2CweMap( CWE_UNKNOWN, vuln.getId(), cwe2cve_map );
        } else {
            if (cwe_list.size() > 1) {
                _println( System.out, "multiple CWE: " + vuln.getId() );
            }
            for (CweReferenceType  cwe : cwe_list) {
                _addCve2CweMap( cwe.getId(), vuln.getId(), cwe2cve_map );
            }
        }
    }


    private void _addCve2CweMap(
                    final String cwe,
                    final String cve,
                    final Map<String,Collection<String>> cwe2cve_map
                    )
    {
        Collection<String>  cve_list = cwe2cve_map.get( cwe );
        if (cve_list == null) {
            cve_list = new TreeSet<String>();
            cwe2cve_map.put( cwe, cve_list );
        }

        cve_list.add( cve );
    }



    private Table _buildNvdCveByCweSimpleReport(
                    final String[] table_header,
                    final Map<String,Collection<String>> cwe2cve_map
                    )
    {
        Table  table = new Table( table_header );
        for (String  cwe : cwe2cve_map.keySet()) {
            Collection<String>  cve_list = cwe2cve_map.get( cwe );
            table.addRow( new Object[] {
                            cwe,
                            cve_list.size(),
                            cve_list
            });
        }

        return table;
    }



    private void _meargeCwe2CveMap(
                    final Map<String,Collection<String>> source_map,
                    final Map<String,Collection<String>> dest_map
                    )
    {
        for (String  cwe : source_map.keySet()) {
            Collection<String>  source_cve_list = source_map.get( cwe );

            Collection<String>  dest_cve_list = dest_map.get( cwe );
            if (dest_cve_list == null) {
                dest_cve_list = new TreeSet<String>();
                dest_map.put( cwe, dest_cve_list );
            }

            dest_cve_list.addAll( source_cve_list );
        }
    }



    private Table _buildNvdCveByCweTotalReport(
                    final String[] table_header,
                    final Map<String,Collection<String>> total_cwe2cve_map,
                    final Map<Integer,Map<String,Collection<String>>> historical_cwe2cve_map
                    //<year,Map<CWE,{CVE}>>
                    )
    {
        Table  table = new Table( table_header );
        for (String  cwe : total_cwe2cve_map.keySet()) {
            Collection<String>  total_cve_list = total_cwe2cve_map.get( cwe );
            List<Object>  row = new ArrayList<Object>();
            row.add( cwe );
            row.add( total_cve_list.size() );

            for (Integer  cve_year : historical_cwe2cve_map.keySet()) {
                // 1999, 2000, ...
                Map<String,Collection<String>>  yearly_cwe2cve_map = historical_cwe2cve_map.get( cve_year );
                Collection<String>  yearly_cve_list = yearly_cwe2cve_map.get( cwe );
                if (yearly_cve_list == null) {
                    row.add( new Integer( 0 ) );
                } else {
                    row.add( yearly_cve_list.size() );
                }
            }

            table.addRow( row );
        }

        return table;
    }




    /**
     * NVD: CVE by Product
     */
    public void statNvdCveByProduct(
                    final int year_begin,
                    final int year_end
                    )
    throws Exception
    {
        String  title = "***** NVD: CVE by Product *****";
        _println( System.out, title );

        final String  filename_prefix = "nvd_cve-by-product_";
        String[]  table_header = new String[] {
                        "Product",
                        "Part",
                        "NVD/CVE",
                        "CVSS (avg.)",
                        "CVE ID"
                        };

        Map<String,Collection<VulnerabilitySummary>>  total_prod2vuln_map =
                        new TreeMap<String,Collection<VulnerabilitySummary>>();

        for (int  cve_year = year_begin; cve_year <= year_end; cve_year++) {
            Map<String,Collection<VulnerabilitySummary>>  prod2vuln_map = _buildYearlyProd2VulnMap( cve_year );
            Table  year_table = _buildNvdCveByProductReport2( table_header, prod2vuln_map );
            _outputReport( year_table, filename_prefix + cve_year );

            _meargeProd2VulnMap( prod2vuln_map, total_prod2vuln_map );
        }

        Table  total_table = _buildNvdCveByProductReport2( table_header, total_prod2vuln_map );
        _outputReport( total_table, filename_prefix + year_begin + "-" + year_end );
    }



    private Map<String,Collection<VulnerabilitySummary>> _buildYearlyProd2VulnMap(
                    final int cve_year
                    )
    throws Exception
    {
        Collection<VulnerabilityType>  vuln_list = _nvd_analyzer.findVulnByCveYear( cve_year );

        Map<String,Collection<VulnerabilitySummary>>  map =
                        new TreeMap<String,Collection<VulnerabilitySummary>>();

        for (VulnerabilityType  vuln : vuln_list) {
            VulnerableSoftwareType  software_list = vuln.getVulnerableSoftwareList();
            if (software_list == null) {
                continue;
            }

            Collection<String>  cpe_list = software_list.getProduct();
            for (String  cpe_name : cpe_list) {
                String  simple_cpe_name = _toSimpleCpeName( cpe_name );

                Collection<VulnerabilitySummary>  product_vuln_list = map.get( simple_cpe_name );
                if (product_vuln_list == null) {
                    product_vuln_list = new TreeSet<VulnerabilitySummary>();
                    map.put( simple_cpe_name, product_vuln_list );
                }

                product_vuln_list.add( new VulnerabilitySummary( vuln ) );
            }
        }

        return map;
    }



    private static final NvdProductMapping  _NVD_PRODUCT_NAME_MAPPING_ =
                    new NvdProductMapping( "/nvd-simple-product-mapping.properties" );

    /**
     * Obtains a simple product name from the CPE name; vendor name, product name, and part name.
     * e.g. "cpe:/a:mysql:mysql:5.5" -> "a:oracle-mysql:mysql" -> "oracle-mysql:mysql,a"
     */
    private static final String _toSimpleCpeName(
                    final String cpe_name
                    )
    {
        String  simple_name = _NVD_PRODUCT_NAME_MAPPING_.toAppropriateSimpleName( cpe_name );
        StringBuilder  s = new StringBuilder();
        s.append( simple_name.substring( 2 ) ).append( ',' ).append( simple_name.charAt( 0 ) );

        return s.toString();
    }



    private Table _buildNvdCveByProductReport2(
                    final String[] header,
                    final Map<String,Collection<VulnerabilitySummary>> prod2vuln_map
                    )
    {
        Table  table = new Table( header );

        for (String  product_name : prod2vuln_map.keySet()) {
            Collection<VulnerabilitySummary>  vuln_list = prod2vuln_map.get( product_name );

            Collection<String>  cve_list = new TreeSet<String>();
            double  cvss_sum = 0.0;
            for (VulnerabilitySummary  vuln : vuln_list) {
                cvss_sum += vuln.cvss_base_score;
                cve_list.add( vuln.cve );
            }
            double  cvss_avg = cvss_sum / vuln_list.size();

            int  index = 0;
            Object[]  values = new Object[table.columns() - 1]; //product_name contains category column
            values[index++] = product_name;
            values[index++] = cve_list.size();

            /* CVSS, e.g. 9.3 */
            Formatter  formatter = new Formatter();
            formatter.format( "%.1f", cvss_avg );
            values[index++] = formatter.out();
            formatter.close();

            values[index++] = cve_list;
            table.addRow( values );
        }

        return table;
    }



    private void _meargeProd2VulnMap(
                    final Map<String,Collection<VulnerabilitySummary>> source_map,
                    final Map<String,Collection<VulnerabilitySummary>> dest_map
                    )
    {
        for (String  product_name : source_map.keySet()) {
            Collection<VulnerabilitySummary>  src_vuln_list = source_map.get( product_name );

            Collection<VulnerabilitySummary>  dest_vuln_list = dest_map.get( product_name );
            if (dest_vuln_list == null) {
                dest_vuln_list = new TreeSet<VulnerabilitySummary>();
                dest_map.put( product_name, dest_vuln_list );
            }

            dest_vuln_list.addAll( src_vuln_list );
        }
    }





    /**
     * OVAL: Coverage of CVE
     */
    public void statOvalCoverageOfCve(
                    final int year_begin,
                    final int year_end
                    )
    throws Exception
    {
        String  title = "***** OVAL: Coverage of CVE *****";
        _println( System.out, title );

        final String  filename_prefix = "oval_coverage-of-cve_";
        String[]  stat_table_header = new String[] {
                        "Year",
                        "NVD/CVE",
                        "OVAL/CVE (Mitre V+P)",
                        "-OVAL/CVE (Mitre V)",
                        "-OVAL/CVE (Mitre P)",
                        "Coverage"
                        };
        Table  stat_table = new Table( stat_table_header );

        String[]  id_table_header = new String[] {
                        "NVD/CVE-ID",
                        "OVAL-IDs"
                        };

        //<year, #NVD/CVE>
        Map<Integer,Long>  nvd_cve_counts = getNumberOfNvdCveEntries( year_begin, year_end );

        for (int  cve_year = year_begin; cve_year <= year_end; cve_year++) {
            //class=VULNERABILITY
            Map<String,Set<String>>  cve2oval_mapping_v =
                            _oval_analyzer.getCve2DefMappingByCveYear( cve_year, ClassEnumeration.VULNERABILITY, OvalRepositoryProvider.MITRE );
            Table  id_table_v = _buildCve2OvalMapping( id_table_header, cve2oval_mapping_v );
            _outputReport( id_table_v, filename_prefix + cve_year + "-mitre-v" );

            //class=PATCH
            Map<String,Set<String>>  cve2oval_mapping_p =
                            _oval_analyzer.getCve2DefMappingByCveYear( cve_year, ClassEnumeration.PATCH, OvalRepositoryProvider.MITRE );
            Table  id_table_p = _buildCve2OvalMapping( id_table_header, cve2oval_mapping_p );
            _outputReport( id_table_p, filename_prefix + cve_year + "-mitre-p" );

            //class=VULNERABILITY & PATCH
            Map<String,Set<String>>  cve2oval_mapping_vp = _mergeCve2OvalMappings( cve2oval_mapping_v, cve2oval_mapping_p );
            Table  id_table_vp = _buildCve2OvalMapping( id_table_header, cve2oval_mapping_vp );
            _outputReport( id_table_vp, filename_prefix + cve_year + "-mitre" );

            long  nvd_cve_count = nvd_cve_counts.get( cve_year );
            int  oval_cve_count = cve2oval_mapping_vp.size();
            Formatter  formatter = new Formatter();
            formatter.format( "%.3f", ((float)oval_cve_count / (float)nvd_cve_count) );
            stat_table.addRow( new Object[] {
                            cve_year,
                            nvd_cve_count,
                            oval_cve_count,
                            cve2oval_mapping_v.size(),
                            cve2oval_mapping_p.size(),
                            formatter.out()
            });

            formatter.close();
        }

        //output//
        _outputReport( stat_table, filename_prefix + year_begin + "-" + year_end );
    }



    private Map<String,Set<String>> _mergeCve2OvalMappings(
                    final Map<String,Set<String>> map1,
                    final Map<String,Set<String>> map2
                    )
    {
        Map<String,Set<String>>  map = new TreeMap<String,Set<String>>( map1 );

        for (String  cve_id : map2.keySet()) {
            Set<String>  oval_ids = map.get( cve_id );
            Set<String>  oval_ids_2 = map2.get( cve_id );
            if (oval_ids == null) {
                oval_ids = oval_ids_2;
            } else {
                oval_ids = new TreeSet<String>( oval_ids );
                oval_ids.addAll( oval_ids_2 );
            }
            map.put( cve_id, oval_ids );
        }

        return map;
    }



    private Table _buildCve2OvalMapping(
                    final String[] header,
                    final Map<String,Set<String>> map
                    )
    {
        Table  table = new Table( header );
        for (String  oval_id : map.keySet()) {
             table.addRow( new Object[] {
                             oval_id,
                             map.get( oval_id )
                             } );
        }

        return table;
    }




    /**
     * OVAL: Def by OS Family
     *
     * Total Stat: {Family, #CVE(1999--2013), #OVAL-Def(1999--2013), #CVE(1999), #OVAL-Def(1999), ..., 2013}
     * CVE by year: {Family, [CVE-IDs]}
     * OVAL by year: {Family, [OVAL-IDs]}
     */
    public void statOvalVulnDefByFamily(
                    final int year_begin,
                    final int year_end
                    )
    throws Exception
    {
        String  title = "***** OVAL: Def by Family *****";
        _println( System.out, title );

        final String  filename_prefix = "oval_def-by-family_";

//        Map<Integer,Map<String,Set<String>>>  historical_family2ovalid_mapping = new HashMap<Integer,Map<String,Set<String>>>();
//        Map<Integer,Map<String,Set<String>>>  historical_family2cveid_mapping  = new HashMap<Integer,Map<String,Set<String>>>();

        Map<String,Set<String>>  total_family2ovalid_mapping = new HashMap<String,Set<String>>();
        Map<String,Set<String>>  total_family2cveid_mapping  = new HashMap<String,Set<String>>();
        for (int  cve_year = year_begin; cve_year <= year_end; cve_year++) {
            //class=VULNERABILITY
            Map<String,Set<DefinitionType>>  family2def_mapping_v =
                            _oval_analyzer.getFamily2DefMappingByCveYear( cve_year, ClassEnumeration.VULNERABILITY, OvalRepositoryProvider.MITRE );
            Map<String,Set<String>>  yearly_family2ovalid_mapping_v = _buildFamily2OvalDefIdMapping( family2def_mapping_v );
            Map<String,Set<String>>  yearly_family2cveid_mapping_v  = _buildFamily2CveIdMapping( family2def_mapping_v, cve_year );

            Table  family2ovalid_table_v = _buildFamily2IdTable( new String[] {
                            "OS-Family",
                            "#OVAL-Def (Mitre V)",
                            "OVAL-Def-ID (Mitre V)"
                            }, yearly_family2ovalid_mapping_v );
            _outputReport( family2ovalid_table_v, filename_prefix + cve_year + "-mitre-v-oval" );
            Table  family2cveid_table_v = _buildFamily2IdTable( new String[] {
                            "OS-Family",
                            "#CVE (Mitre V)",
                            "CVE-ID (Mitre V)"
                            }, yearly_family2cveid_mapping_v );
            _outputReport( family2cveid_table_v, filename_prefix + cve_year + "-mitre-v-cve" );

            _meargeMapping( yearly_family2ovalid_mapping_v, total_family2ovalid_mapping );
            _meargeMapping( yearly_family2cveid_mapping_v,  total_family2cveid_mapping  );

            //class=PATCH
            Map<String,Set<DefinitionType>>  family2def_mapping_p =
                            _oval_analyzer.getFamily2DefMappingByCveYear( cve_year, ClassEnumeration.PATCH, OvalRepositoryProvider.MITRE );
            Map<String,Set<String>>  yearly_family2ovalid_mapping_p = _buildFamily2OvalDefIdMapping( family2def_mapping_p );
            Map<String,Set<String>>  yearly_family2cveid_mapping_p  = _buildFamily2CveIdMapping( family2def_mapping_p, cve_year );

            Table  family2ovalid_table_p = _buildFamily2IdTable( new String[] {
                            "OS-Family",
                            "#OVAL-Def (Mitre P)",
                            "OVAL-Def-ID (Mitre P)"
                            }, yearly_family2ovalid_mapping_p );
            _outputReport( family2ovalid_table_p, filename_prefix + cve_year + "-mitre-p-oval" );
            Table  family2cveid_table_p = _buildFamily2IdTable( new String[] {
                            "OS-Family",
                            "#CVE (Mitre P)",
                            "CVE-ID (Mitre P)"
                            }, yearly_family2cveid_mapping_p );
            _outputReport( family2cveid_table_p, filename_prefix + cve_year + "-mitre-p-cve" );

            _meargeMapping( yearly_family2ovalid_mapping_p, total_family2ovalid_mapping );
            _meargeMapping( yearly_family2cveid_mapping_p,  total_family2cveid_mapping  );


//            historical_family2ovalid_mapping.put( cve_year, yearly_family2ovalid_mapping );
//            historical_family2cveid_mapping.put(  cve_year, yearly_family2cveid_mapping );
        }

        Table  total_table = _buildOvalByFamilyTotalTable(
                        new String[] {
                                        "Family",
                                        "#OVAL-Def (Mitre V+P)",
                                        "#CVE-Covered"
                        },
                        total_family2ovalid_mapping, total_family2cveid_mapping );
        _outputReport( total_table, filename_prefix + year_begin + "-" + year_end );
    }



    private Table _buildOvalByFamilyTotalTable(
                    final String[] header,
                    final Map<String,Set<String>> family2ovalid_map,
                    final Map<String,Set<String>> family2cveid_map
                    )
    {
        Table  table = new Table( header );

        for (String  family : family2ovalid_map.keySet()) {
            table.addRow( new Object[] {
                            family,
                            family2ovalid_map.get( family ).size(),
                            family2cveid_map.get( family ).size(),
            });
        }

        return table;
    }



    private void _meargeMapping(
                    final Map<String,Set<String>> from_map,
                    final Map<String,Set<String>> to_map
                    )
    {
        for (String  key : from_map.keySet()) {
            Set<String>  from_values = from_map.get( key );
            Set<String>    to_values =   to_map.get( key );
            if (to_values == null) {
                to_values = new TreeSet<String>();
                to_map.put( key, to_values );
            }
            to_values.addAll( from_values );
        }
    }



    private Map<String,Set<String>> _buildFamily2OvalDefIdMapping(
                    final Map<String,Set<DefinitionType>> family2def_map
                    )
    {
        Map<String,Set<String>>  family2id_map = new HashMap<String,Set<String>>();
        for (String  family : family2def_map.keySet()) {
            Set<String>  ids = family2id_map.get( family );
            if (ids == null) {
                ids = new TreeSet<String>();
                family2id_map.put( family, ids );
            }
            for (DefinitionType  def : family2def_map.get( family )) {
                ids.add( def.getOvalId() );
            }
        }

        return family2id_map;
    }


    private Table _buildFamily2IdTable(
                    final String[] header,
                    final Map<String,Set<String>> family2id_map
                    )
    {
        Table  table = new Table( header );
        for (String  family : family2id_map.keySet()) {
            Set<String>  ids = family2id_map.get( family );
            table.addRow( new Object[] {
                            family,
                            ids.size(),
                            ids
            } );
        }

        return table;
    }



    private Map<String,Set<String>> _buildFamily2CveIdMapping(
                    final Map<String,Set<DefinitionType>> family2def_map,
                    final int cve_year
                    )
    throws Exception
    {
        final String  cve_prefix = "CVE-" + cve_year + "-";  // e.g. "CVE-2013-"

        Map<String,Set<String>>  family2id_map = new HashMap<String,Set<String>>();
        for (String  family : family2def_map.keySet()) {
            Set<String>  ids = family2id_map.get( family );
            if (ids == null) {
                ids = new TreeSet<String>();
                family2id_map.put( family, ids );
            }
            for (DefinitionType  def : family2def_map.get( family )) {
                Collection<ReferenceType>  ref_list = def.getMetadata().getReference();
                if (ref_list == null) {
                    throw new RuntimeException( "INTERNAL ERROR: NO reference in OVAL Def.: ID="
                    + def.getOvalId() );
                }

                for (ReferenceType  ref : ref_list) {
                    if ("CVE".equals( ref.getSource() )) {
                        String  cve_id = ref.getRefId();
                        if (cve_id.startsWith( cve_prefix )) {
                            if (ids.contains( cve_id )) {
                                _LOG_.warn( "Duplicated CVE Reference: CVE=" + cve_id );
                            }
                            ids.add( cve_id );
                        }
                    }
                }
            }
        }

        return family2id_map;
    }










    ////////////////////////////////////////////////////////////////////////////
    // OLD impl
    ////////////////////////////////////////////////////////////////////////////



    ////////////////////////////////////////////////////////////////////////////
    // OVAL and NVD
    ////////////////////////////////////////////////////////////////////////////


    /**
     * Report: OVAL Coverage of CVE
     *
     * { "Year", "NVD/CVE (except Rejected)", "OVAL (Mitre except Deprecated)", "Coverage", "CVE covered by OVAL" }
     * 1999, nvd-cve_count_1999, oval_count_1999, coverage_1999, [cve-list1]
     * 2000, nvd-cve_count_2000, oval_count_2000, coverage_2000, [cve-list2]
     * ...
     */
    public void reportOvalCoverageOfCve(
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



    ////////////////////////////////////////////////////////////////////////////
    // OVAL
    ////////////////////////////////////////////////////////////////////////////

    public static final String  FAMILY_ERROR = "error";

    /**
     * Report: OVAL: Vulnerability Definitions by OS family.
     *
     *
     */
    public void reportOvalVulnDefByFamily(
                    final int year_begin,
                    final int year_end
                    )
    throws Exception
    {
        String  title = "***** OVAL: Vuln Def by Family *****";
        _println( System.out, title );

        final String  filename_prefix = "oval_vuln-def-by-family_";
        final String[]  year_table_header = new String[] {
                        "Family",
                        "OVAL Vuln Def (except Deprecated)"
                        };

        /* analysis */
        //<year,Map<Family,{OVAL}>>
        Map<Integer,Map<FamilyEnumeration,Collection<String>>>  history_map =
                        new TreeMap<Integer,Map<FamilyEnumeration,Collection<String>>>();

        //Map<Family,{OVAL}>
        Map<FamilyEnumeration,Collection<String>>  total_map =
                        new EnumMap<FamilyEnumeration,Collection<String>>( FamilyEnumeration.class );
        List<String>  total_table_header = new ArrayList<String>( Arrays.asList( year_table_header ) );

        for (int  year = year_begin; year <= year_end; year++) {
            //Map<Family,{OVAL}>
            Map<FamilyEnumeration,Collection<String>>  year_map = _buildOvalFamilyMapOfYear( year );
            Table  year_table = _buildOvalVulnDefByFamilyYearReport( year_table_header, year_map );
            _outputReport( year_table, filename_prefix + year );

            _meargeOvalVulnDefByFamilyMapTo( year_map, total_map );
            total_table_header.add( String.valueOf( year ) );

            history_map.put( new Integer( year ), year_map );
        }

        /* year, total */
        Table  total_table = _buildOvalVulnDefByFamilyTotalReport(
                        total_table_header.toArray( new String[0] ), total_map, history_map );
        _outputReport( total_table, filename_prefix + year_begin + "-" + year_end );
    }



    /**
     * Map: family -> {OVAL Definition ID}
     */
    private Map<FamilyEnumeration,Collection<String>> _buildOvalFamilyMapOfYear(
                    final int year
                    )
    throws Exception
    {
        Collection<DefinitionType>  def_list =
                        _oval_analyzer.findOvalVulnDefExceptDeprecatedByCveYear( year, OvalRepositoryProvider.MITRE );

        Map<FamilyEnumeration,Collection<String>>  map =
                        new EnumMap<FamilyEnumeration,Collection<String>>( FamilyEnumeration.class );
        for (DefinitionType  def : def_list) {
            //def : metadata : affected = 1 : 1 : n
            Collection<AffectedType>  affected_list = def.getMetadata().getAffected();
            if (affected_list == null  ||  affected_list.size() == 0) {
                _println( System.out, "DATA ERROR --- no Affected metadata: " + def.getOvalId() );
                continue;
            }

            for (AffectedType  affected : affected_list) {
                FamilyEnumeration  family = affected.getFamily();
                Collection<String>  oval_id_list = map.get( family );
                if (oval_id_list == null) {
                    oval_id_list = new TreeSet<String>();
                    map.put( family, oval_id_list );
                }
                oval_id_list.add( def.getOvalId() );
            }
        }

        return map;
    }



    /**
     * family, OVAL Def,
     */
    private Table _buildOvalVulnDefByFamilyTotalReport(
                    final String[] table_header,
                    final Map<FamilyEnumeration,Collection<String>> total_map,
                    final Map<Integer,Map<FamilyEnumeration,Collection<String>>> history_map
                    )
    {
        Table  table = new Table( table_header );
        for (FamilyEnumeration  family : total_map.keySet()) {
            Collection<String>  total_oval_id_list = total_map.get( family );
            List<Object>  row = new ArrayList<Object>();
            row.add( family );
            row.add( total_oval_id_list.size() ); //1999--2012

            for (Integer  year : history_map.keySet()) {
                // 1999, 2000, ...
                Map<FamilyEnumeration,Collection<String>>  year_map = history_map.get( year );
                Collection<String>  year_oval_id_list = year_map.get( family );
                if (year_oval_id_list == null) {
                    row.add( new Integer( 0 ) );
                } else {
                    row.add( year_oval_id_list.size() );
                }
            }

            table.addRow( row );
        }

        return table;
    }


    private Table _buildOvalVulnDefByFamilyYearReport(
                    final String[] table_header,
                    final Map<FamilyEnumeration,Collection<String>> family_oval_map
                    )
    {
        Table  table = new Table( table_header );
        for (FamilyEnumeration  family : family_oval_map.keySet()) {
            Collection<String>  oval_id_list = family_oval_map.get( family );
            table.addRow( new Object[] {
                            family,
                            oval_id_list.size(),
                            oval_id_list
            });
        }

        return table;
    }


    private void _meargeOvalVulnDefByFamilyMapTo(
                    final Map<FamilyEnumeration,Collection<String>> source_map,
                    final Map<FamilyEnumeration,Collection<String>> dest_map
                    )
    {
        for (FamilyEnumeration  family : source_map.keySet()) {
            Collection<String>  source_oval_id_list = source_map.get( family );

            Collection<String>  dest_oval_id_list = dest_map.get( family );
            if (dest_oval_id_list == null) {
                dest_oval_id_list = new TreeSet<String>();
                dest_map.put( family, dest_oval_id_list );
            }

            dest_oval_id_list.addAll( source_oval_id_list );
        }
    }



    ////////////////////////////////////////////////////////////////////////////
    // NVD
    ////////////////////////////////////////////////////////////////////////////

    /**
     * Number of NVD/CVE entries by Product, Yearly
     *
     * {Product, CPE Part, #CVE,   AVG(CVSS), CVE ID}
     * product1, h/o/a,    count1, avg_cvss1, [CVE list 1]
     * product2, h/o/a,    count2, avg_cvss2, [CVE list 2]
     * ...
     */
    public void reportNvdCveByProduct(
                    final int year_begin,
                    final int year_end
                    )
    throws Exception
    {
        String  title = "***** NVD: CVE by Product *****";
        _println( System.out, title );

        final String  filename_prefix = "nvd_cve-by-product_";
        String[]  table_header = new String[] {
                        "Product",
                        "CPE Part",
                        "NVD/CVE (except Rejected)",
                        "CVSS (avg.)",
                        "CVE ID (except Rejected)"
                        };

        Map<String,Collection<VulnerabilitySummary>>  total_prod_vuln_map =
                        new TreeMap<String,Collection<VulnerabilitySummary>>();
        for (int  year = year_begin; year <= year_end; year++) {
            Map<String,Collection<VulnerabilitySummary>>  prod_vuln_map =
                            _nvd_analyzer.getVulnExceptRejectedByProductOfYear( year );
            Table  year_table = _buildNvdCveByProductReport( table_header, prod_vuln_map );
            _outputReport( year_table, filename_prefix + year );

            _meargeProductVulnMapTo( prod_vuln_map, total_prod_vuln_map );
        }

        Table  total_table = _buildNvdCveByProductReport( table_header, total_prod_vuln_map );
        _outputReport( total_table, filename_prefix + year_begin + "-" + year_end );
    }



    private Table _buildNvdCveByProductReport(
                    final String[] header,
                    final Map<String,Collection<VulnerabilitySummary>> prod_vuln_map
                    )
    {
        Table  table = new Table( header );

        for (String  product_name : prod_vuln_map.keySet()) {
            Collection<VulnerabilitySummary>  vuln_list = prod_vuln_map.get( product_name );

            Collection<String>  cve_list = new TreeSet<String>();
            double  cvss_sum = 0.0;
            for (VulnerabilitySummary  vuln : vuln_list) {
                cvss_sum += vuln.cvss_base_score;
                cve_list.add( vuln.cve );
            }
            double  cvss_avg = cvss_sum / vuln_list.size();

            int  index = 0;
            Object[]  values = new Object[table.columns() - 1]; //product_name contains category column
            values[index++] = product_name;
            values[index++] = cve_list.size();

            /* CVSS, e.g. 9.3 */
            Formatter  formatter = new Formatter();
            formatter.format( "%.1f", cvss_avg );
            values[index++] = formatter.out();
            formatter.close();

            values[index++] = cve_list;
            table.addRow( values );
        }

        return table;
    }


    private void _meargeProductVulnMapTo(
                    final Map<String,Collection<VulnerabilitySummary>> source_map,
                    final Map<String,Collection<VulnerabilitySummary>> dest_map
                    )
    {
        for (String  product_name : source_map.keySet()) {
            Collection<VulnerabilitySummary>  vuln_list = source_map.get( product_name );

            Collection<VulnerabilitySummary>  product_vuln_list = dest_map.get( product_name );
            if (product_vuln_list == null) {
                product_vuln_list = new TreeSet<VulnerabilitySummary>();
                dest_map.put( product_name, product_vuln_list );
            }

            product_vuln_list.addAll( vuln_list );
        }
    }



    public static final String  CWE_UNKNOWN = "unknown";

    /**
     * NVD: CVE by CWE, yearly.
     *
     * CVE : CWE = 1 : 0..*
     *
     * { "CWE", 1999, ..., 2013 }
     * "unknown" CWE: Entries which contains no CWE property.
     */
    public void reportNvdCveByCwe(
                    final int year_begin,
                    final int year_end
                    )
    throws Exception
    {
        String  title = "***** NVD: CVE by CWE *****";
        _println( System.out, title );

        final String  filename_prefix = "nvd_cve-by-cwe_";
        final String[]  year_table_header = new String[] {
                        "CWE",
                        "NVD/CVE (except Rejected)"
                        };

        String  total_column_name = "Total NVD/CVE (" + year_begin + "--" + year_end + ", except Rejected)";
        final String[]  total_table_header_prefix = new String[] {
                        "CWE",
                        total_column_name,
//                        "1999", "2000", ..., "2012"
                        };

        /* analysis */
        Map<Integer,Map<String,Collection<String>>>  history_cwe_cve_map = new TreeMap<Integer,Map<String,Collection<String>>>();
        //<year,Map<CWE,{CVE}>>

        List<String>  total_table_header = new ArrayList<String>( Arrays.asList( total_table_header_prefix ) );
        Map<String,Collection<String>>  total_cwe_cve_map = new TreeMap<String,Collection<String>>();
        //<CWE,{CVE}>

        for (int  year = year_begin; year <= year_end; year++) {
            Map<String,Collection<String>>  year_cwe_cve_map = new TreeMap<String,Collection<String>>();
            //<CWE,{CVE}>

            List<VulnerabilityType>  vuln_list =  _nvd_analyzer.findVulnExceptRejectedByCveYear( year );
            for (VulnerabilityType  vuln : vuln_list) {
                _analyzeCwe( vuln, year_cwe_cve_map );
            }
            history_cwe_cve_map.put( new Integer( year ), year_cwe_cve_map );

            /* year */
            Table  year_table = _buildNvdCveByCweSimpleReport( year_table_header, year_cwe_cve_map );
            _outputReport( year_table, filename_prefix + year );

            _meargeCweCveMapTo( year_cwe_cve_map, total_cwe_cve_map );
            total_table_header.add( String.valueOf( year ) );
        }

        /* year, total */
        Table  total_table = _buildNvdCveByCweTotalReport(
                        total_table_header.toArray( new String[0] ), total_cwe_cve_map, history_cwe_cve_map );
        _outputReport( total_table, filename_prefix + year_begin + "-" + year_end );
    }



    private void _meargeCweCveMapTo(
                    final Map<String,Collection<String>> source_map,
                    final Map<String,Collection<String>> dest_map
                    )
    {
        for (String  cwe : source_map.keySet()) {
            Collection<String>  source_cve_list = source_map.get( cwe );

            Collection<String>  dest_cve_list = dest_map.get( cwe );
            if (dest_cve_list == null) {
                dest_cve_list = new TreeSet<String>();
                dest_map.put( cwe, dest_cve_list );
            }

            dest_cve_list.addAll( source_cve_list );
        }
    }


    /**
     * Appends a CVE-ID to CWE-CVE map.
     * NVD entry : CWE = 1 : n
     *
     * @param vuln
     * @param cwe_cve_map
     */
    private void _analyzeCwe(
                    final VulnerabilityType vuln,
                    final Map<String,Collection<String>> cwe_cve_map
                    )
    {
        Collection<CweReferenceType>  cwe_list = vuln.getCwe();
        if (cwe_list == null  ||  cwe_list.size() == 0) {
            _println( System.out, "CWE unknown: " + vuln.getId() );
            _addCve2CweMap( CWE_UNKNOWN, vuln.getId(), cwe_cve_map );
        } else {
//            if (cwe_list.size() > 1) {
//                _println( System.out, "multiple CWE: " + vuln.getId() );
//            }
            for (CweReferenceType  cwe : cwe_list) {
                _addCve2CweMap( cwe.getId(), vuln.getId(), cwe_cve_map );
            }
        }
    }


    /**
     * NVD: CVE by CVSS.
     *
     * { "Year", "NVD/CVE (except Rejected),
     *   "High (7.0--10.0)", "Medium (4.0--6.9)", "Low (0.0--3.9)", "Unknown (no CVSS)"" }
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



//DEPRECATED:
//    /**
//     * Report:
//     * @param year_begin
//     * @param year_end
//     */
//    public void reportNumberOfEntries(
//                    final int year_begin,
//                    final int year_end
//                    )
//    throws Exception
//    {
//        String  title = "***** NVD and OVAL: Number of Entries *****";
//        _println( System.out, title );
//
//        final String  filename_prefix = "nvd-oval_entries_";
//        String[]  table_header = new String[] {
//                        "Year",
//                        "NVD/CVE (except Rejected)",
//                        "OVAL (Mitre V/P Def except Deprected)",
//                        "OVAL (Red Hat P Def except Deprecated)"
//                        };
//
//        //analysis//
//        Table  table = new Table( table_header );
//        for (int  year = year_begin; year <= year_end; year++) {
//            long     cve_count =  _nvd_analyzer.countVulnExceptRejectedByCveYear( year );
//            long   mitre_count = _oval_analyzer.countCveAssessmentDefExceptDeprecatedByYear( year, OvalRepositoryProvider.MITRE );
//            long  redhat_count = _oval_analyzer.countCveAssessmentDefExceptDeprecatedByYear( year, OvalRepositoryProvider.REDHAT );
////            long   mitre_count = _oval_analyzer.countOvalVulnDefExceptDeprecatedByCveYear( year, OvalRepositoryProvider.MITRE );
////            long  redhat_count = _oval_analyzer.countOvalVulnDefExceptDeprecatedByCveYear( year, OvalRepositoryProvider.REDHAT );
//
//            table.addRow( new Object[] {
//                            year,
//                            cve_count,
//                            mitre_count,
//                            redhat_count
//            });
//        }
//
//        //output//
//        _outputReport( table, filename_prefix + year_begin + "-" + year_end );
//    }


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
