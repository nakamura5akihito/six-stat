package jp.go.aist.six.stat.tool;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import jp.go.aist.six.stat.model.Table;
import jp.go.aist.six.stat.model.VulnerabilitySummary;
import jp.go.aist.six.util.repository.QueryResults;
import jp.go.aist.six.vuln.core.SixVulnContext;
import jp.go.aist.six.vuln.model.scap.cpe.CpeName;
import jp.go.aist.six.vuln.model.scap.vulnerability.VulnerabilityType;
import jp.go.aist.six.vuln.model.scap.vulnerability.VulnerableSoftwareType;
import jp.go.aist.six.vuln.repository.scap.nvd.NvdRepository;
import jp.go.aist.six.vuln.repository.scap.nvd.VulnerabilityQueryParams;



/**
 */
public class NvdAnalyzer
{

    private NvdRepository  _repository;


    /**
     */
    public NvdAnalyzer()
    {
        setRepository( SixVulnContext.Nvd.repository().getRepository() );
    }



    /**
     */
    public void setRepository(
                    final NvdRepository repository
                    )
    {
        _repository = repository;
    }


    protected NvdRepository _getRepository()
    {
        return _repository;
    }



    /**
     * Number of Entries (yearly)
     *
     * Year, CVE
     * 1999, count1
     * 2000, count2
     * ...
     */
    public Table reportNumberOfEntriesByYear(
                    final int year_begin,
                    final int year_end
                    )
    throws Exception
    {
        String[]  header = new String[] { "Year", "CVE" };
        Table  report = new Table( header );

        List<String>  list = null;
        for (int  year = year_begin; year <= year_end; year++) {
            Object[]  values = new Object[2];
            values[0] = year;

            list = findVulnIdByCveYearExceptRejected( year );
            values[1] = list.size();

            report.addRow( values );
        }

        return report;
    }



    /**
     * {Simple CPE name, CPE part A/O/H, Vulnerability list}
     * vendor:product, part, {Vuln list}
     * vendor:product, part, {Vuln list}
     * ...
     */
    public Map<String,Collection<VulnerabilitySummary>> getVulnExceptRejectedByProductOfYear(
                    final int year
                    )
    throws Exception
    {
        Collection<VulnerabilityType>  vuln_list = findVulnExceptRejectedByCveYear( year );
//        Collection<VulnerabilityType>  vuln_list = findVulnByYear( year );

        Map<String,Collection<VulnerabilitySummary>>  map = new TreeMap<String,Collection<VulnerabilitySummary>>();
        for (VulnerabilityType  vuln : vuln_list) {
            VulnerableSoftwareType  vuln_product_list = vuln.getVulnerableSoftwareList();
            if (vuln_product_list == null) {
                continue;
            }

            Collection<String>  vuln_cpe_list = vuln_product_list.getProduct();
            for (String  vuln_cpe : vuln_cpe_list) {
                String  vuln_simple_cpe = _toSimpleCpeName( vuln_cpe );

                Collection<VulnerabilitySummary>  product_vuln_list = map.get( vuln_simple_cpe );
                if (product_vuln_list == null) {
                    product_vuln_list = new TreeSet<VulnerabilitySummary>();
                    map.put( vuln_simple_cpe, product_vuln_list );
                }

                product_vuln_list.add( new VulnerabilitySummary( vuln ) );
            }
        }

        return map;
    }



    private static final Map<String,String> _createProductAliasNameMapping()
    {
        Map<String,String>  map = new HashMap<String,String>();

        //Mac OS//
        map.put( "apple:os_x_server", "apple:mac_os_x_server" );

        //Mozilla//
        map.put( "mozilla:firefox_esr", "mozilla:firefox" );
        map.put( "mozilla:thunderbird_esr", "mozilla:thunderbird" );

        //Microsoft//
        map.put( "microsoft:windows_2003_server", "microsoft:windows_server_2003" );
        map.put( "microsoft:internet_explorer", "microsoft:ie" );

        //Adobe//
        map.put( "adobe:acrobat_reader", "adobe:adobe_reader" );

        //Sun & Oracle//
        map.put( "sun:jdk",     "sun-oracle:jdk-jre" );
        map.put( "sun:jre",     "sun-oracle:jdk-jre" );
        map.put( "sun:java",    "sun-oracle:jdk-jre" );
        map.put( "sun:java_se", "sun-oracle:jdk-jre" );
        map.put( "sun:j2se",    "sun-oracle:jdk-jre" );
        map.put( "oracle:jdk",  "sun-oracle:jdk-jre" );
        map.put( "oracle:jre",  "sun-oracle:jdk-jre" );

        map.put( "sun:sunos",           "sun-oracle:sunos" );
        map.put( "oracle:sunos",        "sun-oracle:sunos" );
        map.put( "sun:solaris",         "sun-oracle:solaris" );
        map.put( "oracle:solaris",      "sun-oracle:solaris" );
        map.put( "sun:opensolaris",     "sun-oracle:opensolaris" );
        map.put( "oracle:opensolaris",  "sun-oracle:opensolaris" );

        //Red Hat//
        map.put( "red_hat:enterprise_linux",            "redhat:linux" );
        map.put( "red_hat:enterprise_linux_desktop",    "redhat:linux" );
        map.put( "red_hat:enterprise_linux_desktop_workstation",    "redhat:linux" );
        map.put( "red_hat:enterprise_linux_kernel",     "redhat:linux" );
        map.put( "red_hat:linux_kernel",                "redhat:linux" );
        map.put( "red_hat:linux_kernel",                "redhat:linux" );

        map.put( "redhat:desktop",                      "redhat:linux" );
        map.put( "redhat:desktop_workstation",          "redhat:linux" );
        map.put( "redhat:enterprise_linux",             "redhat:linux" );
        map.put( "redhat:enterprise_linux_desktop",     "redhat:linux" );
        map.put( "redhat:enterprise_linux_desktop_workstation",     "redhat:linux" );
        map.put( "redhat:enterprise_linux_server",      "redhat:linux" );
        map.put( "redhat:enterprise_linux_workstation", "redhat:linux" );
        map.put( "redhat:linux_advanced_workstation",   "redhat:linux" );
//        map.put( "redhat:kernel",             "redhat:linux" );


        map.put( "opera:opera",                         "opera:opera_browser" );
        map.put( "opera_software:opera",                "opera:opera_browser" );
        map.put( "opera_software:opera_web_browser",    "opera:opera_browser" );

        map.put( "mysql:mysql",         "mysql-oracle:mysql" );
        map.put( "oracle:mysql",        "mysql-oracle:mysql" );

//        map.put( "macromedia:flash_player",             "adobe:flash_player:" );

        return map;
    }



    private static final Map<String,String>  _PRODUCT_ALIAS_NAME_MAP_ = _createProductAliasNameMapping();

    private static final String _toAliasProductName(
                    final String name
                    )
    {
        String  alias_name = _PRODUCT_ALIAS_NAME_MAP_.get( name );

        return (alias_name == null ? name : alias_name);
    }



    /**
     * Obtains a simple product name from the CPE name; vendor name, product name, and part name.
     * e.g. "cpe:/a:mozilla:firefox:3.5" --> "mozilla:firefox,a"
     */
    private static final String _toSimpleCpeName(
                    final String cpe_name
                    )
    {
        CpeName  cpe = new CpeName( cpe_name );
        String  alias_name = _toAliasProductName( cpe.getVendor() + ":" + cpe.getProduct() );

        StringBuilder  s = new StringBuilder();
        s.append( alias_name );
        s.append( "," ).append( cpe.getPart() );

        return s.toString();
    }




    ///////////////////////////////////////////////////////////////////////
    //  simple functions
    ///////////////////////////////////////////////////////////////////////

    /**
     */
    public long countVulnExceptRejectedByCveYear(
                    final int year
                    )
    throws Exception
    {
        long  count = _getRepository().countVulnerability( createCveYearExceptRejectedQuery( year ) );
        return count;
//        List<String>  list = findVulnIdExceptRejectedByYear( year );
//        return list.size();
    }



    /**
     * Lists the CVE IDs which were released in the specified year.
     */
    public List<String> findVulnIdByCveYearExceptRejected(
                    final int year
                    )
    throws Exception
    {
        QueryResults<String>  query_results =
                        _getRepository().findVulnerabilityId( createCveYearExceptRejectedQuery( year ) );
        List<String>  list = query_results.getElements();

        return list;
    }


    /**
     */
    public List<VulnerabilityType> findVulnIncludingRejectedByCveYear(
                    final int year
                    )
    throws Exception
    {
        QueryResults<VulnerabilityType>  query_results =
                        _getRepository().findVulnerability( createCveYearIncludingRejectedQuery( year ) );
        List<VulnerabilityType>  list = query_results.getElements();

        return list;
    }


    public List<VulnerabilityType> findVulnExceptRejectedByCveYear(
                    final int year
                    )
    throws Exception
    {
        QueryResults<VulnerabilityType>  query_results =
                        _getRepository().findVulnerability( createCveYearExceptRejectedQuery( year ) );
        List<VulnerabilityType>  list = query_results.getElements();

        return list;
    }



    ///////////////////////////////////////////////////////////////////////
    //  Query Params
    ///////////////////////////////////////////////////////////////////////

    /**
     */
    public VulnerabilityQueryParams createCveYearIncludingRejectedQuery(
                    final int year
                    )
    throws Exception
    {
        String  cve_pattern = "CVE-" + year + "-*";
        VulnerabilityQueryParams  params = new VulnerabilityQueryParams();
        params.setId( cve_pattern );

        return params;
    }


    /**
     * The REJECTed entry's summary starts with "** REJECT **  DO NOT USE THIS CANDIDATE NUMBER.".
     */
    public static final String  EXCEPT_REJECTED_PATTERN = "!\\*\\* REJECT \\*\\*";

    public VulnerabilityQueryParams createCveYearExceptRejectedQuery(
                    final int year
                    )
    throws Exception
    {
        VulnerabilityQueryParams  params = createCveYearIncludingRejectedQuery( year );
        params.setSummary( EXCEPT_REJECTED_PATTERN );

        return params;
    }

}
//
