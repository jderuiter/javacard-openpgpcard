package openpgpcard;

import static org.junit.Assert.assertArrayEquals;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import com.licel.jcardsim.base.Simulator;

import javacard.framework.AID;

import openpgpcard.OpenPGPApplet;

public class OpenPGPAppletTest {
	static private byte[] appletAID = new byte[] { (byte) 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x02, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
	static private AID aid = new AID(appletAID, (short) 0, (byte) appletAID.length);
	static private byte[] bArray = new byte[appletAID.length + 1];

	Simulator simulator;

	private static String CHARS = "0123456789ABCDEF";

	public static String bytesToHex(byte[] bytes) {
		StringBuffer hex = new StringBuffer();

		for (int i = 0; i < bytes.length; i++) {
			int n1 = (bytes[i] >> 4) & 0x0F;
			hex.append(CHARS.charAt(n1));
			int n2 = bytes[i] & 0x0F;
			hex.append(CHARS.charAt(n2));
		}

		return hex.toString();
	}

	public static byte[] hexToBytes(String hex) {
		if (hex.length() % 2 != 0)
			hex = "0" + hex;

		byte[] bytes = new byte[hex.length() / 2];

		for (int i = 0; i < hex.length(); i = i + 2) {
			bytes[i / 2] = Integer.decode("0x" + hex.substring(i, i + 2)).byteValue();
		}

		return bytes;
	}

	@BeforeClass
	public static void setUpClass() {
		bArray[0] = (byte) appletAID.length;
		System.arraycopy(appletAID, 0, bArray, 1, appletAID.length);
	}

	@Before
	public void setUp() {
		// Set up the Java Card simulator and install the applet
		simulator = new Simulator();
		simulator.resetRuntime();
		simulator.installApplet(aid, OpenPGPApplet.class, bArray, (short) 0, (byte) bArray.length);
		simulator.selectApplet(aid);
	}

	@Test
	public void test_userPINValid() {
		byte[] response = simulator.transmitCommand(
				new byte[] { 0x00, 0x20, 0x00, (byte) 0x81, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 });
		assertArrayEquals(new byte[] { (byte) 0x90, 0x00 }, response);
	}

	@Test
	public void test_userPINInvalid() {
		byte[] response = simulator.transmitCommand(
				new byte[] { 0x00, 0x20, 0x00, (byte) 0x81, 0x06, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31 });
		assertArrayEquals(new byte[] { (byte) 0x63, (byte) 0xc2 }, response);
		response = simulator.transmitCommand(
				new byte[] { 0x00, 0x20, 0x00, (byte) 0x81, 0x06, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31 });
		assertArrayEquals(new byte[] { (byte) 0x63, (byte) 0xc1 }, response);
		response = simulator.transmitCommand(
				new byte[] { 0x00, 0x20, 0x00, (byte) 0x81, 0x06, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31 });
		assertArrayEquals(new byte[] { (byte) 0x63, (byte) 0xc0 }, response);
		response = simulator.transmitCommand(
				new byte[] { 0x00, 0x20, 0x00, (byte) 0x81, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 });
		assertArrayEquals(new byte[] { (byte) 0x63, (byte) 0xc0 }, response);
	}
	
	@Test
	public void test_userPINStatus() {
		byte[] response = simulator.transmitCommand(
				new byte[] { 0x00, 0x20, 0x00, (byte) 0x81, 0x06, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31 });
		assertArrayEquals(new byte[] { (byte) 0x63, (byte) 0xc2 }, response);
		response = simulator.transmitCommand(
				new byte[] { 0x00, 0x20, 0x00, (byte) 0x81, 0x00 });
		assertArrayEquals(new byte[] { (byte) 0x63, (byte) 0xc2 }, response);
		
		// Verify correct password
		response = simulator.transmitCommand(
				new byte[] { 0x00, 0x20, 0x00, (byte) 0x81, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 });
		assertArrayEquals(new byte[] { (byte) 0x90, 0x00 }, response);
		response = simulator.transmitCommand(
				new byte[] { 0x00, 0x20, 0x00, (byte) 0x81, 0x00 });
		assertArrayEquals(new byte[] { (byte) 0x90, (byte) 0x00 }, response);
		
		// Invalidate correctly verified password
		response = simulator.transmitCommand(
				new byte[] { 0x00, 0x20, (byte)0xFF, (byte) 0x81, 0x00 });
		assertArrayEquals(new byte[] { (byte) 0x90, (byte) 0x00 }, response);
		response = simulator.transmitCommand(		
				new byte[] { 0x00, 0x20, 0x00, (byte) 0x81, 0x00 });
		assertArrayEquals(new byte[] { (byte) 0x63, (byte) 0xc3 }, response);	
	}	

	/**
	 * Test reset of PIN try counter by first verifying a wrong PIN, followed by
	 * a correct PIN and again a wrong PIN. For the second wrong PIN the counter
	 * should be reset to 2 again.
	 */
	@Test
	public void test_userPINReset() {
		byte[] response = simulator.transmitCommand(
				new byte[] { 0x00, 0x20, 0x00, (byte) 0x81, 0x06, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31 });
		assertArrayEquals(new byte[] { (byte) 0x63, (byte) 0xc2 }, response);
		response = simulator.transmitCommand(
				new byte[] { 0x00, 0x20, 0x00, (byte) 0x81, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 });
		assertArrayEquals(new byte[] { (byte) 0x90, (byte) 0x00 }, response);
		response = simulator.transmitCommand(
				new byte[] { 0x00, 0x20, 0x00, (byte) 0x81, 0x06, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31 });
		assertArrayEquals(new byte[] { (byte) 0x63, (byte) 0xc2 }, response);
	}

	@Test
	public void test_generateKey() {
		byte[] response = simulator.transmitCommand(hexToBytes("00200083083132333435363738"));
		assertArrayEquals(new byte[] { (byte) 0x90, (byte) 0x00 }, response);
		response = simulator.transmitCommand(hexToBytes("0047800002B600"));
		byte[] response2 = simulator.transmitCommand(hexToBytes("0047810002B600"));
		assertArrayEquals(response, response2);
	}

	@Test
	public void test_importKey() {
		byte[] response = simulator.transmitCommand(hexToBytes("0047810002B600"));
		assertArrayEquals(new byte[] { (byte) 0x69, (byte) 0x85 }, response);
		response = simulator.transmitCommand(hexToBytes("00200083083132333435363738"));
		assertArrayEquals(new byte[] { (byte) 0x90, (byte) 0x00 }, response);
		response = simulator.transmitCommand(hexToBytes(
				"10DB3FFFFE4D8203A2B6007F48159103928180938180948180958180968180978201005F48820383010001C024584779F7C68DB6299D63E06D8DC029631CED208A03634D648EF4984AB7F79FCF620A81D690D6E98B690AB2444311406B8EC97460931EDC39E74C4047325271D993C97F5216345768E53460121BF78FF984595C00123940575342A2E619BBC5A7C8492453F38CD655F13995770477595279FD2E27409B97928F40E8D01F91EB61C12B9EC0A31213D32975A46C95BAADEF06468DD68CE4858C7E7F94754486825E2673CFA86D3B2764973899882DC1ACB2C19C4E90BFCF319272FF5E86CC1B36FBA96BF3F06DEB9CC6B0BDB1BB4F300A07985BDCE8CAF6"));
		assertArrayEquals(new byte[] { (byte) 0x90, (byte) 0x00 }, response);
		response = simulator.transmitCommand(hexToBytes(
				"10DB3FFFFE11FE3CA640852F0334745FE8B16C9239427CA4A4E7EE406EE2773FE7E447F5F6CFF061EACCCC83B7B2201715989214937C59472FA1BD027FCF3F7727CB14F81C7845988A983452E9B7CA04805126F3C19A1E8E802F39125A7BFD34779036038CBC6D96281BCD1C49C87C9BA16F42667FD33EB472FC17B49B2FFAB3321CCB6BAF1167DA55F9A925BC4243D90F3C9649E9664E048FB44E5771F78F21856E735F12B8B1FA6501822EC23BE959497843853ADCC91F156C7E5C8BC59BED02177A51521E68B3969B01F9591210A51E679BD2EFE044A30D3DC6C12ED8EA70CC6A284ED7798DE88C4322B0133B02BFED3D7108116C0BFE2415ACAFE1C297E7E7C123"));
		assertArrayEquals(new byte[] { (byte) 0x90, (byte) 0x00 }, response);
		response = simulator.transmitCommand(hexToBytes(
				"10DB3FFFFE188B977F632BCD057892AF3000E8A59633C3FF752ED168C482B5003A12659A858CC4B73F70C1A99673B17C39CF555227A0E8BD85C86FCA2374B25D71B5022F81784273293EE9DE5435A237D3B0BF966CF19932A5281A3B0D5FF8C348645E3628B6D286FB1FAE1F194D475FB15A2D1B455CFDE874047B58FDDE412049F9E321A7CAD62B90DE396FFBDA5FFAA320AB125896A399AF66C591927077151692A7B417367CD829A9C3DDEA61E9B0AABBCB33DB653EA3C0B71231305455489E8107B7B0A5400951519DE51C3ACF3C69EE96BC1DFE6A59CAD1F8889433096930E077FC2AEFA0D9104B1230A4AD282BAFA0ED434BAB96D64145B7E8054B88AFF1385C"));
		assertArrayEquals(new byte[] { (byte) 0x90, (byte) 0x00 }, response);
		response = simulator.transmitCommand(hexToBytes(
				"00DB3FFFACFF7879152DC7AC34DD5F17826C177D9173D6094396237A7E560122DFD46F9FBCBFFD27A3E1191F08174F0980BAFDCF45613A03B198C4E6C880E96226AD9E9D3CD08BF05412E8EDD49B267702C2A4766805B38D137191AF2B52991F9ABC49E7C02FCA8C7F617C39CB968894A5A773D5B000912A683F9F760DA6D7247DC26C152CA5DA6FDDD50AD8B769EFB87ADF09B792EDB8AE8B2B3D7015C9F62D7EE3F44F1C35A89140BB74C913A079C3A7"));
		assertArrayEquals(new byte[] { (byte) 0x90, (byte) 0x00 }, response);
		response = simulator.transmitCommand(hexToBytes("0047810002B600"));
		assertArrayEquals(
				hexToBytes(
						"7F4982010981820100B0AABBCB33DB653EA3C0B71231305455489E8107B7B0A5400951519DE51C3ACF3C69EE96BC1DFE6A59CAD1F8889433096930E077FC2AEFA0D9104B1230A4AD282BAFA0ED434BAB96D64145B7E8054B88AFF1385CFF7879152DC7AC34DD5F17826C177D9173D6094396237A7E560122DFD46F9FBCBFFD27A3E1191F08174F0980BAFDCF45613A03B198C4E6C880E96226AD9E9D3CD08BF05412E8EDD49B267702C2A4766805B38D137191AF2B52991F9ABC49E7C02FCA8C7F617C39CB968894A5A773D5B000912A683F9F760DA6D7247DC26C152CA5DA6FDDD50AD8B769EFB87ADF09B792EDB8AE8B2B3D7015C9F62D7EE3F44F1C35A8610F"),
				response);
	}
}
