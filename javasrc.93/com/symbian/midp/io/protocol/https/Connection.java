package com.symbian.midp.io.protocol.https;

import com.nokia.mj.impl.vmport.J9GcfConnectionBase;
import java.io.IOException;

public class Connection extends J9GcfConnectionBase {
	private static Protocol iProtocol = null;

	protected javax.microedition.io.Connection createConnection(String aName, int aMode, boolean aTimeouts)
			throws IOException {
    	int i = aName.indexOf(";nokia_http=1");
    	if(i != -1) {
    		aName = aName.substring(0, i) + aName.substring(i + 13);
            if (iProtocol == null)
            {
                iProtocol = new Protocol();
            }
            return iProtocol.openConnection(aName, aMode, aTimeouts);
    	}
    	return new HttpsConnectionPatched().setParameters2(aName, aMode, aTimeouts);
	}
}
