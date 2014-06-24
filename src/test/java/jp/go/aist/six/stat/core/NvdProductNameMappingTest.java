package jp.go.aist.six.stat.core;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import java.util.Map;
import jp.go.aist.six.stat.tool.NvdProductMapping;
import org.junit.Test;



/**
 */
public class NvdProductNameMappingTest
{

    @Test
    public void test()
    {
//        String  mapping_resource = "/test_nvd-simple-product-mapping.properties";
        String  mapping_resource = "/nvd-simple-product-mapping.properties";

        NvdProductMapping  mapper = new NvdProductMapping( mapping_resource );

        System.out.println( "===== NVD product name pamming =====" );
        Map<String,String>  map = mapper.getMapping();
        for (String  key : map.keySet()) {
            System.out.println( key + " -> " + map.get( key ) );
        }
//        System.out.println( mapper.getMapping() );

        String  appropriate_name = "a:mysql-oracle:mysql";
        String  cpe_name = "cpe:/" + appropriate_name + ":5.0";
        String  mapped_appropriate_name = mapper.toAppropriateSimpleName( cpe_name );
        assertThat( mapped_appropriate_name, is( appropriate_name ) );
    }

}
