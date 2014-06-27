package jp.go.aist.six.stat.model;

import jp.go.aist.six.oval.model.common.ClassEnumeration;





/**
 */
public enum OvalRepositoryProvider
{

    MITRE(  "oval:org.mitre.oval:def:*", new String[] { ClassEnumeration.VULNERABILITY.value(), ClassEnumeration.PATCH.value() } ),
    REDHAT( "oval:com.redhat.rhsa:def:*", new String[] { ClassEnumeration.PATCH.value() });



//    /**
//     * A factory method.
//     */
//    public static OvalRepositoryProvider fromValue(
//                    final String value
//                    )
//    {
//        for (OvalRepositoryProvider  e : OvalRepositoryProvider.values()) {
//            if (e.value.equals( value )) {
//                return e;
//            }
//        }
//
//        throw new IllegalArgumentException( value );
//    }



    private final String  _oval_id_pattern;
    private String[]  _oval_assessment_clazzes;



    /**
     * Constructor.
     */
    OvalRepositoryProvider(
                    final String oval_id_pattern,
                    final String[] oval_assessment_clazzes
                    )
    {
        _oval_id_pattern = oval_id_pattern;
        _oval_assessment_clazzes = oval_assessment_clazzes;
    }



    public String ovalIdPattern()
    {
        return _oval_id_pattern;
    }



    public String[] ovalAssessmentClasses()
    {
        return _oval_assessment_clazzes;
    }



    //**************************************************************
    //  java.lang.Object
    //**************************************************************

//    @Override
//    public String toString()
//    {
//        return name();
//    }

}
//
