package openpgpcard;

import static org.junit.Assert.assertArrayEquals;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import com.licel.jcardsim.base.Simulator;

import javacard.framework.AID;

import openpgpcard.OpenPGPApplet;

public class OpenPGPAppletTest {
    static private byte[] appletAID = new byte[] {(byte)0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
    static private AID aid = new AID(appletAID, (short)0, (byte)appletAID.length);
    static private byte[] bArray = new byte[appletAID.length + 1];
    
    Simulator simulator;
    
    @BeforeClass
    public static void setUpClass() {
		bArray[0] = (byte)appletAID.length;
	    System.arraycopy(appletAID, 0, bArray, 1, appletAID.length);
    }
    
	@Before
	public void setUp() {
		// Set up the Java Card simulator and install the applet
		simulator = new Simulator();
		simulator.resetRuntime();
		simulator.installApplet(aid, OpenPGPApplet.class, bArray, (short)0, (byte)bArray.length);
		simulator.selectApplet(aid);
	}
	
	@Test
	public void test_userPINValid() {
		byte[] response = simulator.transmitCommand(new byte[] {0x00, 0x20, 0x00, (byte)0x81, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36});
		assertArrayEquals(response, new byte[] {(byte)0x90, 0x00});
	}

	@Test
	public void test_userPINInvalid() {
		byte[] response = simulator.transmitCommand(new byte[] {0x00, 0x20, 0x00, (byte)0x81, 0x06, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31});
		assertArrayEquals(response, new byte[] {(byte)0x63, (byte)0xc2});
		response = simulator.transmitCommand(new byte[] {0x00, 0x20, 0x00, (byte)0x81, 0x06, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31});
		assertArrayEquals(response, new byte[] {(byte)0x63, (byte)0xc1});
		response = simulator.transmitCommand(new byte[] {0x00, 0x20, 0x00, (byte)0x81, 0x06, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31});
		assertArrayEquals(response, new byte[] {(byte)0x63, (byte)0xc0});
		response = simulator.transmitCommand(new byte[] {0x00, 0x20, 0x00, (byte)0x81, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36});
		assertArrayEquals(response, new byte[] {(byte)0x63, (byte)0xc0});
	}

	/**
	 * Test reset of PIN try counter by first verifying a wrong PIN, followed by a correct PIN and again a wrong PIN. For the second wrong PIN the counter should be reset to 2 again.
	 */	
	@Test
	public void test_userPINReset() {
		byte[] response = simulator.transmitCommand(new byte[] {0x00, 0x20, 0x00, (byte)0x81, 0x06, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31});
		assertArrayEquals(response, new byte[] {(byte)0x63, (byte)0xc2});
		response = simulator.transmitCommand(new byte[] {0x00, 0x20, 0x00, (byte)0x81, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36});
		assertArrayEquals(response, new byte[] {(byte)0x90, (byte)0x00});
		response = simulator.transmitCommand(new byte[] {0x00, 0x20, 0x00, (byte)0x81, 0x06, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31});
		assertArrayEquals(response, new byte[] {(byte)0x63, (byte)0xc2});
	}
}
