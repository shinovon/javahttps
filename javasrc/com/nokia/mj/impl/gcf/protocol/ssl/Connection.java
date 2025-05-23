/*
* Copyright (c) 2008 Nokia Corporation and/or its subsidiary(-ies).
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of "Eclipse Public License v1.0"
* which accompanies this distribution, and is available
* at the URL "http://www.eclipse.org/legal/epl-v10.html".
*
* Initial Contributors:
* Nokia Corporation - initial contribution.
*
* Contributors:
*
* Description:
*
*/

package com.nokia.mj.impl.gcf.protocol.ssl;

import com.nokia.mj.impl.gcf.utils.J9GcfConnectionBase;

import ru.nnproject.tls.SSLSocket;

import java.io.IOException;

/* This class is specific to j9 Vm.
 * It derives from J9GcfConnectionBase IBM VM's
 * class, so that when Connector.open is called,
 * in case of j9 VM, the VM finds
 * com.nokia.mj.impl.gcf.protocol."scheme".Connection class
 * and calls the createConnection method to return a Connection
 */

public class Connection extends J9GcfConnectionBase {
	private static Protocol iProtocol = null;

	public Connection() {
	}

	protected javax.microedition.io.Connection createConnection(String aName, int aMode, boolean aTimeouts)
			throws IOException {
		int i = aName.indexOf(";nokia_ssl=1");
		if (i != -1) {
			aName = aName.substring(0, i) + aName.substring(i + 12);
			if (iProtocol == null) {
				iProtocol = new Protocol();
			}
			return iProtocol.openConnection(aName, aMode, aTimeouts);
		}
		SSLSocket s = new SSLSocket(aName);
//		s.setTimeouts(aTimeouts);
		return s;
	}
}