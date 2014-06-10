/**
 * SIX STAT
 * Copyright (C) 2014
 *   National Institute of Advanced Industrial Science and Technology (AIST)
 *   Registration Number:
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package jp.go.aist.six.stat.core;

import jp.go.aist.six.util.core.config.spring.SpringContext;



/**
 * Application Context using the Spring Framework.
 *
 * @author  Akihito Nakamura, AIST
 */
public abstract class SixStatContext
    extends SpringContext
{

//    /**
//     * Logger.
//     */
//    private static final Logger  _LOG_ = LoggerFactory.getLogger( SixStatContext.class );




    ///////////////////////////////////////////////////////////////////////

    private static BasicContext            _BASIC_CONTEXT_;


    /**
     * Returns the basic context.
     *
     * @return
     *  the basic context.
     */
    public static synchronized BasicContext instance()
    {
        if (_BASIC_CONTEXT_ == null) {
            _BASIC_CONTEXT_ = new BasicContext();
        }

        return _BASIC_CONTEXT_;
    }




    /**
     * Constructor.
     */
    protected SixStatContext()
    {
    }


    protected SixStatContext(
                    final String config_location
                    )
    {
        super( config_location, new String[] {
                        "classpath:jp/go/aist/six/stat/core/six-stat_defaults.properties",
                        "classpath:six-stat.properties"
                    } );


    }




    ///////////////////////////////////////////////////////////////////////
    //  nested classes
    ///////////////////////////////////////////////////////////////////////

    /**
     * A basic context which supports XML handling only.
     */
    public static class BasicContext
    extends SixStatContext
    {
        public static final String  CONTEXT_PATH =
                        "jp/go/aist/six/stat/core/six-stat_context-basic.xml";


        public BasicContext()
        {
            super( CONTEXT_PATH );
        }

    }
    //

}
//

