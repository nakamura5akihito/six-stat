package jp.go.aist.six.stat.tool;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import jp.go.aist.six.oval.core.SixOvalContext;
import jp.go.aist.six.oval.model.common.ClassEnumeration;
import jp.go.aist.six.oval.model.definitions.DefinitionType;
import jp.go.aist.six.oval.model.definitions.ReferenceType;
import jp.go.aist.six.oval.repository.DefinitionQueryParams;
import jp.go.aist.six.oval.repository.OvalRepository;
import jp.go.aist.six.stat.model.OvalRepositoryProvider;
import jp.go.aist.six.stat.model.Table;
import jp.go.aist.six.util.repository.QueryResults;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



/**
 */
public class OvalAnalyzer
{

    /**
     * Logger.
     */
    private static final Logger  _LOG_ = LoggerFactory.getLogger( OvalAnalyzer.class );



    private OvalRepository  _repository;


    /**
     */
    public OvalAnalyzer()
    {
        setRepository( SixOvalContext.repository().getRepository() );
    }



    /**
     */
    public void setRepository(
                    final OvalRepository repository
                    )
    {
        _repository = repository;
    }


    protected OvalRepository _getRepository()
    {
        return _repository;
    }




    /**
     * Counts the OVAL Definitions.
     *
     * @param cve_year
     *  e.g. 2013
     * @param def_clazz
     *  vulnerability, patch, invertory, etc.
     *  If the clazz is null, then count all the definitions.
     * @param def_provider
     *  Mitre, Red Hat, etc.
     */
    public int countDefByCveYear(
                    final int cve_year,
                    final ClassEnumeration def_clazz,
                    final OvalRepositoryProvider def_provider
                    )
    throws Exception
    {
        DefinitionQueryParams  params = _createDefByCveYearQuery( cve_year, def_clazz, def_provider );
        QueryResults<String>  query_results = _getRepository().findDefinitionId( params );
        return query_results.size();
    }



    /**
     * QUERY:
     */
    private DefinitionQueryParams _createDefByCveYearQuery(
                    final int cve_year,
                    final ClassEnumeration def_clazz,
                    final OvalRepositoryProvider def_provider
                    )
    throws Exception
    {
        if (def_provider == null) {
            throw new NullPointerException( "Empty OVAL provider" );
        }

        DefinitionQueryParams  params = new DefinitionQueryParams();
        params.setDeprecated( "!true" ); //remove "deprecated" definitions

        if (cve_year != 0) {
            params.setRefId( _createCveIdPrefix( cve_year ) + "*" );
        }

        if (def_clazz != null) {
            params.setDefinitionClass( def_clazz );
        }

        params.setId( def_provider.ovalIdPattern() );

        return params;
    }



    /**
     *
     * @param cve_year
     * @param def_clazz
     * @param def_provider
     */
    public List<DefinitionType> findDefByCveYear(
                    final int cve_year,
                    final ClassEnumeration def_clazz,
                    final OvalRepositoryProvider def_provider
                    )
    throws Exception
    {
        DefinitionQueryParams  params = _createDefByCveYearQuery( cve_year, def_clazz, def_provider );
        QueryResults<DefinitionType>  query_results = _getRepository().findDefinition( params );
        List<DefinitionType>  def_list = query_results.getElements();

        return def_list;
    }




    /**
     * {CVE-ID, [OVAL-IDs]}
     */
    public Map<String,Set<String>> getCve2DefMappingByCveYear(
                    final int cve_year,
                    final ClassEnumeration def_clazz,
                    final OvalRepositoryProvider def_provider
                    )
    throws Exception
    {
        List<DefinitionType>  def_list = findDefByCveYear( cve_year, def_clazz, def_provider );
        final String  cve_prefix = _createCveIdPrefix( cve_year );  // e.g. "CVE-2013-"

        //<CVE-ID, [OVAL-IDs]>
        Map<String,Set<String>>  map = new TreeMap<String,Set<String>>();
        for (DefinitionType  def : def_list ) {
            String  oval_id = def.getOvalId();
            Collection<ReferenceType>  ref_list = def.getMetadata().getReference();
            if (ref_list == null) {
                //INTERNAL ERROR!
                throw new RuntimeException( "INTERNAL ERROR: NO reference in OVAL Def.: ID=" + oval_id );
            }

            for (ReferenceType  ref : ref_list) {
                if ("CVE".equals( ref.getSource() )) {
                    String  cve_id = ref.getRefId();
                    if (cve_id.startsWith( cve_prefix )) {
                        Set<String>  oval_ids = map.get( cve_id );
                        if (oval_ids == null) {
                            oval_ids = new TreeSet<String>();
                            map.put( cve_id, oval_ids );
                        }
                        oval_ids.add( oval_id );
                    }
                }
            }
        }

        return map;
    }




    /**
     * {OVAL-ID, [CVE-IDs]}
     */
    public Map<String,Set<String>> getDef2CveMappingByCveYear(
                    final int cve_year,
                    final ClassEnumeration def_clazz,
                    final OvalRepositoryProvider def_provider
                    )
    throws Exception
    {
        List<DefinitionType>  def_list = findDefByCveYear( cve_year, def_clazz, def_provider );
        final String  cve_prefix = _createCveIdPrefix( cve_year );  // e.g. "CVE-2013-"

        //<OVAL-ID, {CVE-IDs}>
        Map<String,Set<String>>  map = new HashMap<String,Set<String>>();
        for (DefinitionType  def : def_list ) {
            Set<String>  cve_ids = new TreeSet<String>();
            Collection<ReferenceType>  ref_list = def.getMetadata().getReference();
            if (ref_list != null) {
                for (ReferenceType  ref : ref_list) {
                    if ("CVE".equals( ref.getSource() )) {
                        String  cve_id = ref.getRefId();
                        if (cve_id.startsWith( cve_prefix )) {
                            cve_ids.add( cve_id );
                        }
                    }
                }
            }

            if (cve_ids.size() == 0) {
                _LOG_.error( "INTERNAL ERROR: OVAL Def has NO appropriate CVE Ref: OVAL ID="
                                + def.getOvalId() + ", CVE year=" + cve_year );
            }
            map.put( def.getOvalId(), cve_ids );

        }

        return map;
    }








    ////////////////////////////////////////////////////////////////////////////
    //  OLD impl
    ////////////////////////////////////////////////////////////////////////////


    /**
     * 2012 --> {CVE-2012-0001, CVE-2012-0002, ...}
     */
    public Set<String> findCveIdFromVulnDefExceptDeprecatedByCveYear(
                    final int year,
                    final OvalRepositoryProvider provider
                    )
    throws Exception
    {
        DefinitionQueryParams  params = _createOvalVulnDefExceptDeprecatedQuery( year, provider );
        QueryResults<DefinitionType>  query_results = _getRepository().findDefinition( params );
        List<DefinitionType>  def_list = query_results.getElements();

        final String  cve_prefix = _createCveIdPrefix( year );  // e.g. "CVE-2012-"

        Set<String>  cve_set = new TreeSet<String>();
        for (DefinitionType  def : def_list) {
            if (def.getDeprecated() == Boolean.TRUE) {
                _LOG_.warn( "INTERNAL ERROR: OVAL query result includes deprecated Definition: "
                            + def.getOvalId() );
                continue;
            }

            Collection<ReferenceType>  ref_list = def.getMetadata().getReference();
            if (ref_list != null) {
                for (ReferenceType  ref : ref_list) {
                    if ("CVE".equals( ref.getSource() )) {
                        String  cve_id = ref.getRefId();
                        if (cve_id.startsWith( cve_prefix )) {
                            cve_set.add( cve_id );
                        }
                    }
                }
            }
        }

        return cve_set;
    }



    private String _createCveIdPrefix(
                    final int year // 0 means all the years
                    )
    {
        String  prefix = "CVE-";
        if (year != 0) {
            prefix += year + "-";
        }

        return prefix;
    }



    /**
     * QueryParams:
     */
    private DefinitionQueryParams _createOvalVulnDefExceptDeprecatedQuery(
                    final int year, // 0 means all the years
                    final OvalRepositoryProvider provider
                    )
    throws Exception
    {
        if (provider == null) {
            throw new NullPointerException( "Empty OVAL provider" );
        }

        DefinitionQueryParams  params = new DefinitionQueryParams();
        params.setDeprecated( "!true" );    //remove "deprecated" definitions
        params.setRefId( _createCveIdPrefix( year ) + "*" );

        if (provider == OvalRepositoryProvider.MITRE) {
            params.setDefinitionClass( ClassEnumeration.VULNERABILITY );
            params.setId( "oval:org.mitre.oval:def:*" );
        } else if (provider == OvalRepositoryProvider.REDHAT) {
            params.setDefinitionClass( ClassEnumeration.PATCH );
            params.setId( "oval:com.redhat.rhsa:def:*" );
        }

        return params;
    }



    /**
     * 2012 --> {oval:org.mitre.oval:def:xxx, oval:org.mitre.oval:def:yyy, ...}
     */
    public Collection<DefinitionType> findOvalVulnDefExceptDeprecatedByCveYear(
                    final int year,
                    final OvalRepositoryProvider provider
                    )
    throws Exception
    {
        DefinitionQueryParams  params = _createOvalVulnDefExceptDeprecatedQuery( year, provider );
        QueryResults<DefinitionType>  query_results = _getRepository().findDefinition( params );
        return query_results.getElements();
    }



    /**
     * 2012 --> 446 = |{oval:org.mitre.oval:def:xxx, oval:org.mitre.oval:def:yyy, ...}|
     */
    public int countOvalVulnDefExceptDeprecatedByCveYear(
                    final int year,
                    final OvalRepositoryProvider provider
                    )
    throws Exception
    {
        DefinitionQueryParams  params = _createOvalVulnDefExceptDeprecatedQuery( year, provider );
        QueryResults<String>  query_results = _getRepository().findDefinitionId( params );
        return query_results.size();
    }


//DEPRECATED:
//  /**
//   * Counts the OVAL Definitions to assess the CVE vulnerabilities.
//   *
//   * @param year
//   * @param provider
//   * @return
//   *  the number of OVAL Definitions.
//   */
//  public int countCveAssessmentDefExceptDeprecatedByYear(
//                  final int year,
//                  final OvalRepositoryProvider provider
//                  )
//  throws Exception
//  {
//      DefinitionQueryParams  params = _createYearlyCveAssessmentDefQuery( year, provider );
//      QueryResults<String>  query_results = _getRepository().findDefinitionId( params );
//      return query_results.size();
//  }




    /**
     * Number of Entries (yearly)
     * -- number of definitions whose class is vuln(Mitre) or patch(RedHat) --
     *
     * Year, OVALs (Mitre), OVALs(Red Hat)
     * 1999, countM1,       countR1
     * 2000, countM2,       countR2
     * ...
     */
    public Table reportNumberOfEntriesByYear(
                    final int year_begin,
                    final int year_end
                    )
    throws Exception
    {
        String[]  header = new String[] { "Year", "OVALs (Mitre)", "OVALs(Red Hat)" };
        Table  report = new Table( header );

//        List<DefinitionType>  def_list = null;
        for (int  year = year_begin; year <= year_end; year++) {
            Object[]  values = new Object[3];
            values[0] = year;

            int  mitre_count = countOvalVulnDefExceptDeprecatedByCveYear( year, OvalRepositoryProvider.MITRE );
            values[1] = mitre_count;
            int  redhat_count = countOvalVulnDefExceptDeprecatedByCveYear( year, OvalRepositoryProvider.REDHAT );
            values[2] = redhat_count;

//            def_list = _findVulnDefByYearMitre( year );
//            values[1] = def_list.size();
//            def_list = _findVulnDefByYearRedHat( year );
//            values[2] = def_list.size();

            report.addRow( values );
        }

        return report;
    }



    ///////////////////////////////////////////////////////////////////////
    //  query
    ///////////////////////////////////////////////////////////////////////

//DEPRECATED:
//    /**
//     *
//     * @param cve_year  CVE-ID year, e.g. 2013 for CVE-2013-2465. 0 means all the years.
//     * @param def_clazzes OVAL Definition class; vulnerability, patch, etc. Null means all the classes.
//     * @param provider  Mitre, Red Hat, etc.
//     */
//    private DefinitionQueryParams _createYearlyCveAssessmentDefQuery(
//                    final int cve_year,
//                    final OvalRepositoryProvider provider
//                    )
//    throws Exception
//    {
//        if (provider == null) {
//            throw new NullPointerException( "Empty OVAL provider" );
//        }
//
//        DefinitionQueryParams  params = new DefinitionQueryParams();
//        params.setDeprecated( "!true" ); //remove "deprecated" definitions
//
//        if (cve_year != 0) {
//            params.setRefId( _createCveIdPrefix( cve_year ) + "*" );
//        }
//
//        params.setDefinitionClass( provider.ovalAssessmentClasses() );
//
//        params.setId( provider.ovalIdPattern() );
//
//        return params;
//    }




    ///////////////////////////////////////////////////////////////////////
    //  support functions
    ///////////////////////////////////////////////////////////////////////

//    /**
//     * Mitre OVAL Def, vulnerability class
//     */
//    private List<DefinitionType> _findVulnDefByYearMitre(
//                    final int year
//                    )
//    throws Exception
//    {
//        return _findVulnDef( ClassEnumeration.VULNERABILITY,
//                        "oval:org.mitre.oval:def:*",
//                        "CVE-" + year + "-*"
//                        );
//    }
//
//
//    /**
//     * Red Hat OVAL Def, patch class
//     */
//    private List<DefinitionType> _findVulnDefByYearRedHat(
//                    final int year
//                    )
//    throws Exception
//    {
//        return _findVulnDef( ClassEnumeration.PATCH,
//                        "oval:com.redhat.rhsa:def:*",
//                        "CVE-" + year + "-*"
//                        );
//    }
//
//
//    /**
//     */
//    private List<DefinitionType> _findVulnDef(
//                    final ClassEnumeration  def_class,
//                    final String oval_id_pattern,
//                    final String cve_pattern
//                    )
//    throws Exception
//    {
//        DefinitionQueryParams  params = new DefinitionQueryParams();
//        params.setDefinitionClass( def_class );
//        params.setId( oval_id_pattern );
//        params.setDeprecated( "!true" );    //remove "deprecated" definitions
//        params.setRefId( cve_pattern );
//
//        QueryResults<DefinitionType>  query_results = _getRepository().findDefinition( params );
//        List<DefinitionType>  def_list = query_results.getElements();
//
//        return def_list;
//    }

}
//
