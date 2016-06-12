package cn.gov.se;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
/**
 * 在金融SE发卡过程中存放卡片序列号
 * @author wangzhaoguo
 */
public class Main extends Applet {

	private byte[] seid = new byte[10];

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new Main().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) {

		byte[] buffer = apdu.getBuffer();
		buffer[0] = (byte) (buffer[0] & 0xFC);

		// 选择应用
		if (selectingApplet()) {
			
			GPSystem.getSecureChannel().resetSecurity();

			Util.arrayCopyNonAtomic(seid, (short) 0, buffer, (short) 0, (short) seid.length);
			apdu.setOutgoingAndSend((short) 0, (short) seid.length);
			return;
		}

		// 指令的安全性管理
		byte[] buf = apduSecurityManager(apdu);
		if (buf == null) {
			return;
		}

		switch (buf[ISO7816.OFFSET_INS]) {
		case (byte) 0xE2:

			short lc = (short) (buf[ISO7816.OFFSET_LC] & 0x0FF);
			if (lc != seid.length)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

			Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, seid, (short) 0, (short) seid.length);

			break;
		default:

			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	/**
	 * 指令的合法性检查，外部认证，指令解密处理
	 * 
	 * @param apdu
	 * @return
	 */
	private byte[] apduSecurityManager(APDU apdu) {

		// 获取指令数据
		byte[] buf = apdu.getBuffer();

		// 外部认证
		if (extAuth(buf, apdu)) {
			return null;
		}

		// 接收指令
		short lc = (short) (buf[ISO7816.OFFSET_LC] & 0x0FF);
		if (lc > 0)
			apdu.setIncomingAndReceive();

		// 判断外部认证是否成功
		if ((GPSystem.getSecureChannel().getSecurityLevel() & SecureChannel.AUTHENTICATED) != SecureChannel.AUTHENTICATED) {
			if (!((byte) 0xCA == buf[ISO7816.OFFSET_INS] && (byte) 0x50 == buf[ISO7816.OFFSET_P2])) {
				ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
			}
		}

		// 解密APDU指令
		if (GPSystem.getSecureChannel().getSecurityLevel() != SecureChannel.AUTHENTICATED) {
			short len = (short) (buf[ISO7816.OFFSET_LC] & 0x0FF);
			GPSystem.getSecureChannel().unwrap(buf, (short) 0, (short) (len + 5));
		}

		buf[0] = (byte) (buf[0] & 0xFC);
		return buf;
	}

	/**
	 * 外部认证
	 * 
	 * @param buf
	 * @param apdu
	 */
	private boolean extAuth(byte[] buf, APDU apdu) {

		if ((byte) 0x80 == buf[ISO7816.OFFSET_CLA] && (byte) 0x50 == buf[ISO7816.OFFSET_INS]) {
			GPSystem.getSecureChannel().resetSecurity();
			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, GPSystem.getSecureChannel().processSecurity(apdu));
			return true;

		} else if (((byte) 0x84 == buf[ISO7816.OFFSET_CLA] && (byte) 0x82 == buf[ISO7816.OFFSET_INS])) {
			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, GPSystem.getSecureChannel().processSecurity(apdu));
			return true;
		}
		return false;
	}
}
