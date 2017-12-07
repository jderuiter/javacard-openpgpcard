package openpgpcard;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.licel.jcardsim.smartcardio.CardSimulator;

import javacard.framework.AID;

public class OpenPGPAppletTest {
	static int CLA_DEFAULT = 0x00;
	static int CLA_CHAINING = 0x10;
	static int CLA_SM = 0x0C;
	static int CLA_SM_CHAINING = 0x1C;
	
	static int INS_SELECT = 0xA4;
	static int INS_SELECT_DATA = 0xA5;
	static int INS_GET_DATA = 0xCA;
	static int INS_GET_NEXT_DATA = 0xCC;
	static int INS_VERIFY = 0x20;
	static int INS_CHANGE_REFERENCE_DATA = 0x24;
	static int INS_RESET_RETRY_COUNTER = 0x2C;
	static int INS_PUT_DATA_DA = 0xDA;
	static int INS_PUT_DATA_DB = 0xDB;
	static int INS_GENERATE_ASYMMETYRIC_KEY_PAIR = 0x47;
	static int INS_PERFORM_SECURITY_OPERATION = 0x2A;
	static int INS_INTERNAL_AUTHENTICATE = 0x88;
	static int INS_GET_RESPONSE = 0xC0;
	static int INS_GET_CHALLENGE = 0x84;
	static int INS_TERMINATE_DF = 0xE6;
	static int INS_ACTIVATE_FILE = 0x44;
	static int INS_MANAGE_SECURITY_ENVIRONMENT = 0x22;
	
	static int SW_NO_ERROR = 0x9000;
	static int SW_WARNING_STATE_UNCHANGED = 0x6200;
	static int SW_TRIES_REMAINING_0 = 0x63c0;
	static int SW_TRIES_REMAINING_1 = 0x63c1;
	static int SW_TRIES_REMAINING_2 = 0x63c2;
	static int SW_TRIES_REMAINING_3 = 0x63c3;	
	static int SW_WRONG_LENGTH = 0x6700;
	static int SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982;
	static int SW_AUTHENTICATION_METHOD_BLOCKED = 0x6983;
	static int SW_DATA_INVALID = 0x6984;
	static int SW_CONDITIONS_NOT_SATISFIED = 0x6985;
	static int SW_RECORD_NOT_FOUND = 0x6a83;
	static int SW_INCORRECT_P1P2 = 0x6a86;
	static int SW_INS_NOT_SUPPORTED = 0x6d00;
	static int SW_UNKNOWN = 0x6f00;
	
	static private byte[] appletAID = new byte[] { (byte) 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x02, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
	static private AID aid = new AID(appletAID, (short) 0, (byte) appletAID.length);
	static private byte[] bArray = new byte[appletAID.length + 1];

	CardSimulator simulator;
	CommandAPDU command;
	
	// Test data
	static byte[] USER_PIN_DEFAULT = new byte[] { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
	static byte[] USER_PIN_INVALID = new byte[] { 0x31, 0x31, 0x31, 0x31, 0x31, 0x31 };
	static byte[] USER_PIN_NEW = new byte[] { 0x36, 0x35, 0x34, 0x33, 0x32, 0x31 };
	
	static byte[] ADMIN_PIN_DEFAULT = new byte[] { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
	static byte[] ADMIN_PIN_INVALID = new byte[] { 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31 };
	static byte[] ADMIN_PIN_NEW = new byte[] { 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31 };
	
	RSAPublicKey publicKey;
	SecretKeySpec aes128KeySpec;
	SecretKeySpec aes256KeySpec;
	IvParameterSpec ivSpec = new IvParameterSpec(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });	
	
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
	
	public ResponseAPDU test(CommandAPDU command, int expectedSW, byte[] expectedData) {
		ResponseAPDU response = simulator.transmitCommand(command);		
		assertEquals(expectedSW, response.getSW());
		
		if(expectedData != null) {
			assertArrayEquals(expectedData, response.getData());
		}
		
		return response;
	}
	
	public ResponseAPDU test(CommandAPDU command, int expectedSW) {
		return test(command, expectedSW, new byte[] {});
	}

	@BeforeClass
	public static void setUpClass() {
		bArray[0] = (byte) appletAID.length;
		System.arraycopy(appletAID, 0, bArray, 1, appletAID.length);
	}

	@Before
	public void setUp() throws NoSuchAlgorithmException, InvalidKeySpecException {
		// Set up the Java Card simulator and install the applet
		simulator = new CardSimulator();
		simulator.resetRuntime();
		simulator.installApplet(aid, OpenPGPApplet.class, bArray, (short) 0, (byte) bArray.length);
		simulator.selectApplet(aid);
		
		// Construct RSA public key
		RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger("B0AABBCB33DB653EA3C0B71231305455489E8107B7B0A5400951519DE51C3ACF3C69EE96BC1DFE6A59CAD1F8889433096930E077FC2AEFA0D9104B1230A4AD282BAFA0ED434BAB96D64145B7E8054B88AFF1385CFF7879152DC7AC34DD5F17826C177D9173D6094396237A7E560122DFD46F9FBCBFFD27A3E1191F08174F0980BAFDCF45613A03B198C4E6C880E96226AD9E9D3CD08BF05412E8EDD49B267702C2A4766805B38D137191AF2B52991F9ABC49E7C02FCA8C7F617C39CB968894A5A773D5B000912A683F9F760DA6D7247DC26C152CA5DA6FDDD50AD8B769EFB87ADF09B792EDB8AE8B2B3D7015C9F62D7EE3F44F1C35A89140BB74C913A079C3A7", 16), new BigInteger("010001", 16));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
		
		// Construct AES keys
		aes128KeySpec = new SecretKeySpec(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, "AES");
		aes256KeySpec = new SecretKeySpec(new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, "AES");
	}

	@Test
	public void test_userPINValid81() {
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0x00, 0x81, USER_PIN_DEFAULT);
		test(command, SW_NO_ERROR);
	}

	@Test
	public void test_userPINValid82() {
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0x00, 0x82, USER_PIN_DEFAULT);
		test(command, SW_NO_ERROR);
	}
	
	@Test
	public void test_userPINInvalid() {
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0x00, 0x81, USER_PIN_INVALID);
		test(command, SW_SECURITY_STATUS_NOT_SATISFIED);
		
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0x00, 0x81, USER_PIN_INVALID);
		test(command, SW_SECURITY_STATUS_NOT_SATISFIED);
		
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0x00, 0x81, USER_PIN_INVALID);
		test(command, SW_SECURITY_STATUS_NOT_SATISFIED);
		
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0x00, 0x81, USER_PIN_INVALID);
		test(command, SW_AUTHENTICATION_METHOD_BLOCKED);
	}
	
	@Test
	public void test_userPINStatus() {
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0x00, 0x81, USER_PIN_INVALID);
		test(command, SW_SECURITY_STATUS_NOT_SATISFIED);
		
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0x00, 0x81);
		test(command, SW_TRIES_REMAINING_2);
		
		// Verify correct PIN
		test_userPINValid81();
		
		// Invalidate correctly verified PIN
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0xFF, 0x81);
		test(command, SW_NO_ERROR);

		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0x00, 0x81);
		test(command, SW_TRIES_REMAINING_3);		
	}	
	
	@Test
	public void test_adminPINValid() {
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0x00, 0x83, ADMIN_PIN_DEFAULT);
		test(command, SW_NO_ERROR);
	}	
	
	@Test
	public void test_userPINResetRC() {
		test_adminPINValid();
		
		// Set RC
		command = new CommandAPDU(CLA_DEFAULT, INS_PUT_DATA_DA, 0x00, 0xD3, new byte[] { 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31 });
		test(command, SW_NO_ERROR);
		
		// Invalidate correctly verified admin PIN
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0xFF, 0x83);
		test(command, SW_NO_ERROR);

		// Verify admin PIN was reset
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0x00, 0x83);
		test(command, SW_TRIES_REMAINING_3);
		
		// Block user PIN
		test_userPINInvalid();
		
		// Reset user PIN using RC PIN
		command = new CommandAPDU(CLA_DEFAULT, INS_RESET_RETRY_COUNTER, 0x00, 0x81, new byte[] { 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31 });
		test(command, SW_NO_ERROR);	
		
		// Check the counter is reset
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0x00, 0x81);
		test(command, SW_TRIES_REMAINING_3);
		
		// Verify new user PIN
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0x00, 0x81, new byte[] { 0x31, 0x31, 0x31, 0x31, 0x31, 0x31 });
		test(command, SW_NO_ERROR);
	}
	
	@Test
	public void test_userPINResetAdmin() {
		// Block user PIN
		test_userPINInvalid();
		
		// Reset user PIN without verifying admin password
		command = new CommandAPDU(CLA_DEFAULT, INS_RESET_RETRY_COUNTER, 0x02, 0x81, USER_PIN_NEW);
		test(command, SW_SECURITY_STATUS_NOT_SATISFIED);
		
		// Reset user PIN after verifying admin password		
		test_adminPINValid();		
		command = new CommandAPDU(CLA_DEFAULT, INS_RESET_RETRY_COUNTER, 0x02, 0x81, USER_PIN_NEW);
		test(command, SW_NO_ERROR);
		
		// Check the counter is reset
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0x00, 0x81);
		test(command, SW_TRIES_REMAINING_3);
		
		// Verify new user PIN
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0x00, 0x81, USER_PIN_NEW);
		test(command, SW_NO_ERROR);	
	}		

	/**
	 * Test reset of PIN try counter by first verifying a wrong PIN, followed by
	 * a correct PIN and again a wrong PIN. For the second wrong PIN the counter
	 * should be reset to 2 again.
	 */
	@Test
	public void test_userPINReset() {
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0x00, 0x81, USER_PIN_INVALID);
		test(command, SW_SECURITY_STATUS_NOT_SATISFIED);

		// Check there is one less try for the PIN
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0x00, 0x81);
		test(command, SW_TRIES_REMAINING_2);
		
		test_userPINValid81();

		// Reset PIN status
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0xFF, 0x81);
		test(command, SW_NO_ERROR);
		
		// Check there are again 3 tries remaining for the PIN
		command = new CommandAPDU(CLA_DEFAULT, INS_VERIFY, 0x00, 0x81);
		test(command, SW_TRIES_REMAINING_3);		
	}

	@Test
	public void test_generateKey() {
		test_adminPINValid();
		
		command = new CommandAPDU(CLA_DEFAULT, INS_GENERATE_ASYMMETYRIC_KEY_PAIR, 0x80, 0x00, new byte[] {(byte)0xB6, 0x00});
		ResponseAPDU response1 = test(command, 0x610f, null);
		
		command = new CommandAPDU(CLA_DEFAULT, INS_GET_RESPONSE, 0x00, 0x00, 0x0f);
		ResponseAPDU response2 = test(command, SW_NO_ERROR, null);
		
		command = new CommandAPDU(CLA_DEFAULT, INS_GENERATE_ASYMMETYRIC_KEY_PAIR, 0x81, 0x00, new byte[] {(byte)0xB6, 0x00});
		test(command, 0x610f, response1.getData());
		
		command = new CommandAPDU(CLA_DEFAULT, INS_GET_RESPONSE, 0x00, 0x00, 0x0f);
		test(command, SW_NO_ERROR, response2.getData());
	}

	@Test
	public void test_importSignKey() {
		// Test whether a key is already present
		command = new CommandAPDU(CLA_DEFAULT, INS_GENERATE_ASYMMETYRIC_KEY_PAIR, 0x81, 0x00, new byte[] {(byte)0xB6, 0x00});
		test(command, SW_CONDITIONS_NOT_SATISFIED);

		test_adminPINValid();

		// Import key
		command = new CommandAPDU(CLA_CHAINING, INS_PUT_DATA_DB, 0x3F, 0xFF, hexToBytes("4D8203A2B6007F48159103928180938180948180958180968180978201005F48820383010001C024584779F7C68DB6299D63E06D8DC029631CED208A03634D648EF4984AB7F79FCF620A81D690D6E98B690AB2444311406B8EC97460931EDC39E74C4047325271D993C97F5216345768E53460121BF78FF984595C00123940575342A2E619BBC5A7C8492453F38CD655F13995770477595279FD2E27409B97928F40E8D01F91EB61C12B9EC0A31213D32975A46C95BAADEF06468DD68CE4858C7E7F94754486825E2673CFA86D3B2764973899882DC1ACB2C19C4E90BFCF319272FF5E86CC1B36FBA96BF3F06DEB9CC6B0BDB1BB4F300A07985BDCE8CAF6"));
		test(command, SW_NO_ERROR);
		
		command = new CommandAPDU(CLA_CHAINING, INS_PUT_DATA_DB, 0x3F, 0xFF, hexToBytes("11FE3CA640852F0334745FE8B16C9239427CA4A4E7EE406EE2773FE7E447F5F6CFF061EACCCC83B7B2201715989214937C59472FA1BD027FCF3F7727CB14F81C7845988A983452E9B7CA04805126F3C19A1E8E802F39125A7BFD34779036038CBC6D96281BCD1C49C87C9BA16F42667FD33EB472FC17B49B2FFAB3321CCB6BAF1167DA55F9A925BC4243D90F3C9649E9664E048FB44E5771F78F21856E735F12B8B1FA6501822EC23BE959497843853ADCC91F156C7E5C8BC59BED02177A51521E68B3969B01F9591210A51E679BD2EFE044A30D3DC6C12ED8EA70CC6A284ED7798DE88C4322B0133B02BFED3D7108116C0BFE2415ACAFE1C297E7E7C123"));
		test(command, SW_NO_ERROR);

		command = new CommandAPDU(CLA_CHAINING, INS_PUT_DATA_DB, 0x3F, 0xFF, hexToBytes("188B977F632BCD057892AF3000E8A59633C3FF752ED168C482B5003A12659A858CC4B73F70C1A99673B17C39CF555227A0E8BD85C86FCA2374B25D71B5022F81784273293EE9DE5435A237D3B0BF966CF19932A5281A3B0D5FF8C348645E3628B6D286FB1FAE1F194D475FB15A2D1B455CFDE874047B58FDDE412049F9E321A7CAD62B90DE396FFBDA5FFAA320AB125896A399AF66C591927077151692A7B417367CD829A9C3DDEA61E9B0AABBCB33DB653EA3C0B71231305455489E8107B7B0A5400951519DE51C3ACF3C69EE96BC1DFE6A59CAD1F8889433096930E077FC2AEFA0D9104B1230A4AD282BAFA0ED434BAB96D64145B7E8054B88AFF1385C"));
		test(command, SW_NO_ERROR);
		
		command = new CommandAPDU(CLA_DEFAULT, INS_PUT_DATA_DB, 0x3F, 0xFF, hexToBytes("FF7879152DC7AC34DD5F17826C177D9173D6094396237A7E560122DFD46F9FBCBFFD27A3E1191F08174F0980BAFDCF45613A03B198C4E6C880E96226AD9E9D3CD08BF05412E8EDD49B267702C2A4766805B38D137191AF2B52991F9ABC49E7C02FCA8C7F617C39CB968894A5A773D5B000912A683F9F760DA6D7247DC26C152CA5DA6FDDD50AD8B769EFB87ADF09B792EDB8AE8B2B3D7015C9F62D7EE3F44F1C35A89140BB74C913A079C3A7"));
		test(command, SW_NO_ERROR);

		// Verify that the key was properly imported
		command = new CommandAPDU(CLA_DEFAULT, INS_GENERATE_ASYMMETYRIC_KEY_PAIR, 0x81, 0x00, new byte[] {(byte)0xB6, 0x00});
		test(command, 0x610f, hexToBytes("7F4982010981820100B0AABBCB33DB653EA3C0B71231305455489E8107B7B0A5400951519DE51C3ACF3C69EE96BC1DFE6A59CAD1F8889433096930E077FC2AEFA0D9104B1230A4AD282BAFA0ED434BAB96D64145B7E8054B88AFF1385CFF7879152DC7AC34DD5F17826C177D9173D6094396237A7E560122DFD46F9FBCBFFD27A3E1191F08174F0980BAFDCF45613A03B198C4E6C880E96226AD9E9D3CD08BF05412E8EDD49B267702C2A4766805B38D137191AF2B52991F9ABC49E7C02FCA8C7F617C39CB968894A5A773D5B000912A683F9F760DA6D7247DC26C152CA5DA6FDDD50AD8B769EFB87ADF09B792EDB8AE8B2B3D7015C9F62D7EE3F44F1C35A8"));

		command = new CommandAPDU(CLA_DEFAULT, INS_GET_RESPONSE, 0x00, 0x00, 0x0f);
		test(command, SW_NO_ERROR, hexToBytes("9140BB74C913A079C3A78203010001"));	
	}
	
	@Test
	public void test_importDecryptKey() {
		// Test whether a key is already present
		command = new CommandAPDU(CLA_DEFAULT, INS_GENERATE_ASYMMETYRIC_KEY_PAIR, 0x81, 0x00, new byte[] {(byte)0xB8, 0x00});
		test(command, SW_CONDITIONS_NOT_SATISFIED);

		test_adminPINValid();

		// Import key
		command = new CommandAPDU(CLA_CHAINING, INS_PUT_DATA_DB, 0x3F, 0xFF, hexToBytes("4D8203A2B8007F48159103928180938180948180958180968180978201005F48820383010001C024584779F7C68DB6299D63E06D8DC029631CED208A03634D648EF4984AB7F79FCF620A81D690D6E98B690AB2444311406B8EC97460931EDC39E74C4047325271D993C97F5216345768E53460121BF78FF984595C00123940575342A2E619BBC5A7C8492453F38CD655F13995770477595279FD2E27409B97928F40E8D01F91EB61C12B9EC0A31213D32975A46C95BAADEF06468DD68CE4858C7E7F94754486825E2673CFA86D3B2764973899882DC1ACB2C19C4E90BFCF319272FF5E86CC1B36FBA96BF3F06DEB9CC6B0BDB1BB4F300A07985BDCE8CAF6"));
		test(command, SW_NO_ERROR);
		
		command = new CommandAPDU(CLA_CHAINING, INS_PUT_DATA_DB, 0x3F, 0xFF, hexToBytes("11FE3CA640852F0334745FE8B16C9239427CA4A4E7EE406EE2773FE7E447F5F6CFF061EACCCC83B7B2201715989214937C59472FA1BD027FCF3F7727CB14F81C7845988A983452E9B7CA04805126F3C19A1E8E802F39125A7BFD34779036038CBC6D96281BCD1C49C87C9BA16F42667FD33EB472FC17B49B2FFAB3321CCB6BAF1167DA55F9A925BC4243D90F3C9649E9664E048FB44E5771F78F21856E735F12B8B1FA6501822EC23BE959497843853ADCC91F156C7E5C8BC59BED02177A51521E68B3969B01F9591210A51E679BD2EFE044A30D3DC6C12ED8EA70CC6A284ED7798DE88C4322B0133B02BFED3D7108116C0BFE2415ACAFE1C297E7E7C123"));
		test(command, SW_NO_ERROR);

		command = new CommandAPDU(CLA_CHAINING, INS_PUT_DATA_DB, 0x3F, 0xFF, hexToBytes("188B977F632BCD057892AF3000E8A59633C3FF752ED168C482B5003A12659A858CC4B73F70C1A99673B17C39CF555227A0E8BD85C86FCA2374B25D71B5022F81784273293EE9DE5435A237D3B0BF966CF19932A5281A3B0D5FF8C348645E3628B6D286FB1FAE1F194D475FB15A2D1B455CFDE874047B58FDDE412049F9E321A7CAD62B90DE396FFBDA5FFAA320AB125896A399AF66C591927077151692A7B417367CD829A9C3DDEA61E9B0AABBCB33DB653EA3C0B71231305455489E8107B7B0A5400951519DE51C3ACF3C69EE96BC1DFE6A59CAD1F8889433096930E077FC2AEFA0D9104B1230A4AD282BAFA0ED434BAB96D64145B7E8054B88AFF1385C"));
		test(command, SW_NO_ERROR);
		
		command = new CommandAPDU(CLA_DEFAULT, INS_PUT_DATA_DB, 0x3F, 0xFF, hexToBytes("FF7879152DC7AC34DD5F17826C177D9173D6094396237A7E560122DFD46F9FBCBFFD27A3E1191F08174F0980BAFDCF45613A03B198C4E6C880E96226AD9E9D3CD08BF05412E8EDD49B267702C2A4766805B38D137191AF2B52991F9ABC49E7C02FCA8C7F617C39CB968894A5A773D5B000912A683F9F760DA6D7247DC26C152CA5DA6FDDD50AD8B769EFB87ADF09B792EDB8AE8B2B3D7015C9F62D7EE3F44F1C35A89140BB74C913A079C3A7"));
		test(command, SW_NO_ERROR);

		// Verify that the key was properly imported
		command = new CommandAPDU(CLA_DEFAULT, INS_GENERATE_ASYMMETYRIC_KEY_PAIR, 0x81, 0x00, new byte[] {(byte)0xB8, 0x00});
		test(command, 0x610f, hexToBytes("7F4982010981820100B0AABBCB33DB653EA3C0B71231305455489E8107B7B0A5400951519DE51C3ACF3C69EE96BC1DFE6A59CAD1F8889433096930E077FC2AEFA0D9104B1230A4AD282BAFA0ED434BAB96D64145B7E8054B88AFF1385CFF7879152DC7AC34DD5F17826C177D9173D6094396237A7E560122DFD46F9FBCBFFD27A3E1191F08174F0980BAFDCF45613A03B198C4E6C880E96226AD9E9D3CD08BF05412E8EDD49B267702C2A4766805B38D137191AF2B52991F9ABC49E7C02FCA8C7F617C39CB968894A5A773D5B000912A683F9F760DA6D7247DC26C152CA5DA6FDDD50AD8B769EFB87ADF09B792EDB8AE8B2B3D7015C9F62D7EE3F44F1C35A8"));

		command = new CommandAPDU(CLA_DEFAULT, INS_GET_RESPONSE, 0x00, 0x00, 0x0f);
		test(command, SW_NO_ERROR, hexToBytes("9140BB74C913A079C3A78203010001"));
	}	
	
	@Test
	public void test_sign() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		byte[] testData = new byte[] { (byte)0xAB };
		
		test_importSignKey();
		test_userPINValid81();
		
		command = new CommandAPDU(CLA_DEFAULT, INS_PERFORM_SECURITY_OPERATION, 0x9E, 0x9A, testData);
		ResponseAPDU response1 = test(command, 0x6101, hexToBytes("9E62CCBC302E5FF18C897FC65CA5F5044FDFA2133B53778CA10CF75F929428FADC8135958884DCD7829E32DC3D69D902364DDB37448420DDC9F5F57955CC6CCFD869A32E280482C207877B80CE953352E4B41291E624F7583BA84DC5655D5FEC06FE85304470227337C11F21B3528C0EB626ED01F7AE2DD57BA6F7D2529401EF03047394AFE00B626D65FBB57EE59273D6A37E0CA0BF9958BE75F15989CB77BFC18D445EAD7103B857B6B446B0AA35392B1E902C5B2D31E5B7F1A419016EBAFDE3DF22E42417E870907AF4FF0D376EFF188BD919476CF7F95A013D130ED096F6E5D79F8488B2114AC5D1FA989946411CD571F4DB27247477939457FEA734FF"));
		
		command = new CommandAPDU(CLA_DEFAULT, INS_GET_RESPONSE, 0x00, 0x00, 0x01);
		ResponseAPDU response2 = test(command, SW_NO_ERROR, hexToBytes("DB"));
		
		byte[] signedData = new byte[response1.getNr() + response2.getNr()];
		System.arraycopy(response1.getData(), 0, signedData, 0, response1.getNr());
		System.arraycopy(response2.getData(), 0, signedData, response1.getNr(), response2.getNr());
		
		Cipher cipher = Cipher.getInstance("RSA");
	    cipher.init(Cipher.DECRYPT_MODE, publicKey);
	    byte[] plaintextData = cipher.doFinal(signedData);
	    assertArrayEquals(testData, plaintextData);
	}	
	
	@Test
	public void test_signWrongPINMode() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		byte[] testData = new byte[] { (byte)0xAB };
		
		test_importSignKey();
		test_userPINValid82();
		
		command = new CommandAPDU(CLA_DEFAULT, INS_PERFORM_SECURITY_OPERATION, 0x9E, 0x9A, testData);
		test(command, SW_SECURITY_STATUS_NOT_SATISFIED);
	}		
	
	@Test
	public void test_signTwice() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		byte[] testData = new byte[] { (byte)0xAB };
		
		test_importSignKey();
		test_userPINValid81();
		
		command = new CommandAPDU(CLA_DEFAULT, INS_PERFORM_SECURITY_OPERATION, 0x9E, 0x9A, testData);
		test(command, 0x6101, hexToBytes("9E62CCBC302E5FF18C897FC65CA5F5044FDFA2133B53778CA10CF75F929428FADC8135958884DCD7829E32DC3D69D902364DDB37448420DDC9F5F57955CC6CCFD869A32E280482C207877B80CE953352E4B41291E624F7583BA84DC5655D5FEC06FE85304470227337C11F21B3528C0EB626ED01F7AE2DD57BA6F7D2529401EF03047394AFE00B626D65FBB57EE59273D6A37E0CA0BF9958BE75F15989CB77BFC18D445EAD7103B857B6B446B0AA35392B1E902C5B2D31E5B7F1A419016EBAFDE3DF22E42417E870907AF4FF0D376EFF188BD919476CF7F95A013D130ED096F6E5D79F8488B2114AC5D1FA989946411CD571F4DB27247477939457FEA734FF"));
		
		command = new CommandAPDU(CLA_DEFAULT, INS_GET_RESPONSE, 0x00, 0x00, 0x01);
		test(command, SW_NO_ERROR, hexToBytes("DB"));
		
		command = new CommandAPDU(CLA_DEFAULT, INS_PERFORM_SECURITY_OPERATION, 0x9E, 0x9A, testData);
		test(command, SW_SECURITY_STATUS_NOT_SATISFIED);	
	}		
	
	@Test
	public void test_signTwicePWStatus1() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		byte[] testData = new byte[] { (byte)0xAB };
		
		test_importSignKey();
		
		// Enable multiple signatures per authentication
		test_adminPINValid();
		command = new CommandAPDU(CLA_DEFAULT, INS_PUT_DATA_DA, 0x00, 0xC4, new byte[] { 0x01 });
		test(command, SW_NO_ERROR);
		
		test_userPINValid81();
		
		command = new CommandAPDU(CLA_DEFAULT, INS_PERFORM_SECURITY_OPERATION, 0x9E, 0x9A, testData);
		test(command, 0x6101, hexToBytes("9E62CCBC302E5FF18C897FC65CA5F5044FDFA2133B53778CA10CF75F929428FADC8135958884DCD7829E32DC3D69D902364DDB37448420DDC9F5F57955CC6CCFD869A32E280482C207877B80CE953352E4B41291E624F7583BA84DC5655D5FEC06FE85304470227337C11F21B3528C0EB626ED01F7AE2DD57BA6F7D2529401EF03047394AFE00B626D65FBB57EE59273D6A37E0CA0BF9958BE75F15989CB77BFC18D445EAD7103B857B6B446B0AA35392B1E902C5B2D31E5B7F1A419016EBAFDE3DF22E42417E870907AF4FF0D376EFF188BD919476CF7F95A013D130ED096F6E5D79F8488B2114AC5D1FA989946411CD571F4DB27247477939457FEA734FF"));
		
		command = new CommandAPDU(CLA_DEFAULT, INS_GET_RESPONSE, 0x00, 0x00, 0x01);
		test(command, SW_NO_ERROR, hexToBytes("DB"));
		
		command = new CommandAPDU(CLA_DEFAULT, INS_PERFORM_SECURITY_OPERATION, 0x9E, 0x9A, testData);
		test(command, 0x6101, hexToBytes("9E62CCBC302E5FF18C897FC65CA5F5044FDFA2133B53778CA10CF75F929428FADC8135958884DCD7829E32DC3D69D902364DDB37448420DDC9F5F57955CC6CCFD869A32E280482C207877B80CE953352E4B41291E624F7583BA84DC5655D5FEC06FE85304470227337C11F21B3528C0EB626ED01F7AE2DD57BA6F7D2529401EF03047394AFE00B626D65FBB57EE59273D6A37E0CA0BF9958BE75F15989CB77BFC18D445EAD7103B857B6B446B0AA35392B1E902C5B2D31E5B7F1A419016EBAFDE3DF22E42417E870907AF4FF0D376EFF188BD919476CF7F95A013D130ED096F6E5D79F8488B2114AC5D1FA989946411CD571F4DB27247477939457FEA734FF"));

		command = new CommandAPDU(CLA_DEFAULT, INS_GET_RESPONSE, 0x00, 0x00, 0x01);
		test(command, SW_NO_ERROR, hexToBytes("DB"));
	}	
	
	@Test
	public void test_decrypt() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		byte[] testData = new byte[] { (byte)0xAB };

	    Cipher cipher = Cipher.getInstance("RSA");
	    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	    byte[] encryptedData = cipher.doFinal(testData);
	    
		test_importDecryptKey();
		test_userPINValid82();
		
		byte[] data = new byte[255];
		data[0] = 0x00;
		System.arraycopy(encryptedData, 0, data, 1, 254);
		
		command = new CommandAPDU(CLA_CHAINING, INS_PERFORM_SECURITY_OPERATION, 0x80, 0x86, data);
		test(command, SW_NO_ERROR);

		data = new byte[encryptedData.length - 254];
		System.arraycopy(encryptedData, 254, data, 0, data.length);
		command = new CommandAPDU(CLA_DEFAULT, INS_PERFORM_SECURITY_OPERATION, 0x80, 0x86, data);
		test(command, SW_NO_ERROR, testData);
	}	
	
	@Test
	public void test_decryptWrongPINMode() {
		byte[] testData = new byte[] { (byte)0xAB };
		
		test_importDecryptKey();
		test_userPINValid81();
		
		command = new CommandAPDU(CLA_DEFAULT, INS_PERFORM_SECURITY_OPERATION, 0x80, 0x86, testData);
		test(command, SW_SECURITY_STATUS_NOT_SATISFIED);
	}
	
	@Test
	public void test_encryptAES128() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		byte[] testData = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

		Cipher aesCipher = Cipher.getInstance("AES/CBC/NOPADDING");
		aesCipher.init(Cipher.ENCRYPT_MODE, aes128KeySpec, ivSpec);
		byte[] encryptedData = aesCipher.doFinal(testData);
		
		test_adminPINValid();
		// Import AES key
		command = new CommandAPDU(CLA_DEFAULT, INS_PUT_DATA_DA, 0x00, 0xD5, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 });
		test(command, SW_NO_ERROR);		
		
		test_userPINValid82();
		
		command = new CommandAPDU(CLA_DEFAULT, INS_PERFORM_SECURITY_OPERATION, 0x86, 0x80, testData);
		test(command, SW_NO_ERROR, hexToBytes("02" + bytesToHex(encryptedData)));
	}	
	
	@Test
	public void test_decryptAES128() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		byte[] testData = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
		
		Cipher aesCipher = Cipher.getInstance("AES/CBC/NOPADDING");
		aesCipher.init(Cipher.ENCRYPT_MODE, aes128KeySpec, ivSpec);
		byte[] encryptedData = aesCipher.doFinal(testData);
		
		test_adminPINValid();
		// Import AES key
		command = new CommandAPDU(CLA_DEFAULT, INS_PUT_DATA_DA, 0x00, 0xD5, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 });
		test(command, SW_NO_ERROR);		
		
		test_userPINValid82();
		
		command = new CommandAPDU(CLA_DEFAULT, INS_PERFORM_SECURITY_OPERATION, 0x80, 0x86, hexToBytes("02" + bytesToHex(encryptedData)));
		test(command, SW_NO_ERROR, testData);
	}
	
	@Test
	public void test_encryptDecryptAES128() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		byte[] testData = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
		
		test_adminPINValid();
		// Import AES key
		command = new CommandAPDU(CLA_DEFAULT, INS_PUT_DATA_DA, 0x00, 0xD5, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 });
		test(command, SW_NO_ERROR);		
		
		test_userPINValid82();
		
		command = new CommandAPDU(CLA_DEFAULT, INS_PERFORM_SECURITY_OPERATION, 0x86, 0x80, testData);
		ResponseAPDU response = test(command, SW_NO_ERROR, null);
		
		command = new CommandAPDU(CLA_DEFAULT, INS_PERFORM_SECURITY_OPERATION, 0x80, 0x86, response.getData());
		test(command, SW_NO_ERROR, testData);
	}	
	
	@Test
	public void test_encryptAES256() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		byte[] testData = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

		Cipher aesCipher = Cipher.getInstance("AES/CBC/NOPADDING");
		aesCipher.init(Cipher.ENCRYPT_MODE, aes256KeySpec, ivSpec);
		byte[] encryptedData = aesCipher.doFinal(testData);
		
		test_adminPINValid();
		// Import AES key
		command = new CommandAPDU(CLA_DEFAULT, INS_PUT_DATA_DA, 0x00, 0xD5, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 });
		test(command, SW_NO_ERROR);		
		
		test_userPINValid82();
		
		command = new CommandAPDU(CLA_DEFAULT, INS_PERFORM_SECURITY_OPERATION, 0x86, 0x80, testData);
		test(command, SW_NO_ERROR, hexToBytes("02" + bytesToHex(encryptedData)));	
	}	
	
	@Test
	public void test_decryptAES256() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		byte[] testData = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

		Cipher aesCipher = Cipher.getInstance("AES/CBC/NOPADDING");
		aesCipher.init(Cipher.ENCRYPT_MODE, aes256KeySpec, ivSpec);
		byte[] encryptedData = aesCipher.doFinal(testData);
		
		test_adminPINValid();
		// Import AES key
		command = new CommandAPDU(CLA_DEFAULT, INS_PUT_DATA_DA, 0x00, 0xD5, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 });
		test(command, SW_NO_ERROR);		
		
		test_userPINValid82();
		
		command = new CommandAPDU(CLA_DEFAULT, INS_PERFORM_SECURITY_OPERATION, 0x80, 0x86, hexToBytes("02" + bytesToHex(encryptedData)));
		test(command, SW_NO_ERROR, testData);
	}		
	
	@Test
	public void test_encryptDecryptAES256() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		byte[] testData = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
		
		test_adminPINValid();
		// Import AES key
		command = new CommandAPDU(CLA_DEFAULT, INS_PUT_DATA_DA, 0x00, 0xD5, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 });
		test(command, SW_NO_ERROR);		
		
		test_userPINValid82();
		
		command = new CommandAPDU(CLA_DEFAULT, INS_PERFORM_SECURITY_OPERATION, 0x86, 0x80, testData);
		ResponseAPDU response = test(command, SW_NO_ERROR, null);
		
		command = new CommandAPDU(CLA_DEFAULT, INS_PERFORM_SECURITY_OPERATION, 0x80, 0x86, response.getData());
		test(command, SW_NO_ERROR, testData);
	}	
}
