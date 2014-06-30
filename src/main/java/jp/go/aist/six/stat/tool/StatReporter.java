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
import jp.go.aist.six.stat.model.OvalRepositoryProvider;
import jp.go.aist.six.stat.model.Table;
import jp.go.aist.six.stat.model.VulnerabilitySummary;
import jp.go.aist.six.vuln.model.scap.cvss.BaseMetricsType;
import jp.go.aist.six.vuln.model.scap.cvss.CvssImpactType;
import jp.go.aist.six.vuln.model.scap.vulnerability.CweReferenceType;
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
//        reporter.statNumberOfEntries( PERIOD_BEGIN, PERIOD_END );
//        reporter.statNvdCveByCvss( PERIOD_BEGIN, PERIOD_END );
        reporter.statNvdCveByCwe( PERIOD_BEGIN, PERIOD_END );

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
    {
        _output_dir = _mkOutputDirs();

        _nvd_analyzer = new NvdAnalyzer();
        _oval_analyzer = new OvalAnalyzer();
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

        //analysis//
        Table  table = new Table( table_header );
        for (int  cve_year = year_begin; cve_year <= year_end; cve_year++) {
            long       cve_count =  _nvd_analyzer.countVulnByCveYear( cve_year );
            long   mitre_v_count = _oval_analyzer.countDefByYear( cve_year, ClassEnumeration.VULNERABILITY, OvalRepositoryProvider.MITRE );
            long   mitre_p_count = _oval_analyzer.countDefByYear( cve_year, ClassEnumeration.PATCH, OvalRepositoryProvider.MITRE );
            long  redhat_p_count = _oval_analyzer.countDefByYear( cve_year, ClassEnumeration.PATCH, OvalRepositoryProvider.REDHAT );

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


        /* analysis */
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
