package jp.go.aist.six.stat.core;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import java.util.Map;
import org.junit.Test;



/**
 */
public class NvdProductNameMappingTest
{

    @Test
    public void test()
    {
        NvdProductMapping  mapper =
                        new NvdProductMapping( "/test_nvd-simple-product-mapping.properties" );

        System.out.println( "===== NVD product name pamming =====" );
        Map<String,String>  map = mapper.getMapping();
        for (String  key : map.keySet()) {
            System.out.println( key + " -> " + map.get( key ) );
        }
//        System.out.println( mapper.getMapping() );

        String  simple_name = "a:mysql:mysql";
        String  cpe_name = "cpe:/" + simple_name + ":5.0";
        String  appropriate_name = mapper.toAppropriateSimpleName( cpe_name );
        assertThat( appropriate_name, is( simple_name ) );
    }

}
