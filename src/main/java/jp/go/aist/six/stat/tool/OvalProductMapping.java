package jp.go.aist.six.stat.tool;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import jp.go.aist.six.util.config.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



/**
 */
public class OvalProductMapping
{

    /**
     * Logger.
     */
    private static final Logger  _LOG_ = LoggerFactory.getLogger( OvalProductMapping.class );




    /**
     * alternative name -> appropriate name
     */
    private Map<String,String>  _product_name_map;




    /**
     */
    public OvalProductMapping(
                    final String product_name_map_resource
                    )
    {
        _buildProductNameMap( product_name_map_resource );
    }




    /**
     * Returns the appropriate product name for the specified CPE name.
     * The returned name is a simple name: except for the CPE schema part "cpe:/".
     */
    public String toAppropriateName(
                    final String product_name
                    )
    {
        String  appropriate_name = _product_name_map.get( product_name );

        return (appropriate_name == null ? product_name : appropriate_name);
    }



    /**
     *
     * @return
     */
    public Map<String,String> getMapping()
    {
        return _product_name_map;
    }



    /**
     * Builds the alternate-appropriate product name mapping from a resource file.
     *
     * @param product_name_map_resource
     */
    protected void _buildProductNameMap(
                    final String product_name_map_resource
                    )
    {
        InputStream  input = null;
        try {
            URL  url = getClass().getResource( product_name_map_resource );
            _LOG_.debug( "OVAL product name map resource: " + url );
            input = url.openStream();
            _product_name_map = _readMapping( input );
        } catch (IOException ex) {
            throw new ConfigurationException( ex );
        } finally {
            try {
                input.close();
            } catch (Exception ignorable) {
            }
        }
    }



    /**
     * Reads the mapping information from the stream.
     *
     * @param input
     * @return
     *  unmodifiable Map; keys are the alternative names and values are the appropriate names.
     * @throws IOException
     */
    private Map<String,String> _readMapping(
                    final InputStream input
                    )
    throws IOException
    {
        BufferedReader  reader = new BufferedReader( new InputStreamReader( input ) );
        Map<String,String>  map = new HashMap<String,String>();
        while (true) {
            String  line = reader.readLine();
            if (line == null) {
                break; //end of stream//
            }
            if (line.length() == 0) {
                continue;
            }
            if (line.charAt( 0 ) == '#') {
                //comment line//
                continue;
            }

            String[]  key_value = line.split( "\\s*=\\s*" );
            if (key_value.length < 2) {
                throw new ConfigurationException( "invalid product name mapping: " + line );
            }
            String  appropriate_name = key_value[0];
            _LOG_.debug( "appropriate name: " + appropriate_name );
            _LOG_.debug( "    alternative names: " + key_value[1] );

            String[]  alternative_names = key_value[1].split( ",\\s*" );
            for (String  alternative_name : alternative_names) {
                String  existing_appropriate_name = map.get( alternative_name );
                if (existing_appropriate_name != null) {
                    String  message = "duplicate alternative name mapping: "
                                    + alternative_name + " -> " + existing_appropriate_name;
                    _LOG_.error( message );
                    throw new ConfigurationException( message );
                }
                map.put( alternative_name, appropriate_name );
            }
        }

        return Collections.unmodifiableMap( map );
    }

}
//
