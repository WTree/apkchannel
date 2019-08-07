package com.cobra.zip;

import com.cobra.zip.Util.Pair;
import com.cobra.zip.Util.ZipUtils;
import com.cobra.zip.exception.SignatureNotFoundException;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static com.cobra.zip.ApkSigningBlockUtils.*;

public class ZipHelper {


    public static final int SF_ATTRIBUTE_ANDROID_APK_SIGNED_ID = 2;
    private static final int APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a;

    private static final long APK_SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42L;
    private static final long APK_SIG_BLOCK_MAGIC_LO = 0x20676953204b5041L;
    private static final int APK_SIG_BLOCK_MIN_SIZE = 32;
    private static final int ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET = 16;

    private final static int CHANNEL_FLAG = 0x12345678;   //渠道id标识


    public static int readChannel(RandomAccessFile apk) throws Exception {


        //根据标识（0x06054b50）找到EOCD
        Pair<ByteBuffer, Long> eocdAndOffsetInFile = getEocd(apk);
        ByteBuffer eocd = eocdAndOffsetInFile.first;
        long eocdOffset = eocdAndOffsetInFile.second;

        if (ZipUtils.isZip64EndOfCentralDirectoryLocatorPresent(apk, eocdOffset)) {
            throw new SignatureNotFoundException("ZIP64 APK not supported");
        }

        //查找中央目录位移
        long centralDirOffset = getCentralDirOffset(eocd, eocdOffset);

        //查找签名块位移
        Pair<ByteBuffer, Long> apkSigningBlockAndOffsetInFile = findApkSigningBlock(apk, centralDirOffset);

        ByteBuffer footer = ByteBuffer.allocate(16);
        footer.order(ByteOrder.LITTLE_ENDIAN);
        int pos = (int) (apkSigningBlockAndOffsetInFile.second + 8);
        apk.seek(pos);//再把指针移动到指定位置，插入追加的数据
        apk.readFully(footer.array(), 0, footer.capacity());


        System.out.println("size:"+footer.getLong(0));
        System.out.println("head："+footer.getInt(8));

        if(footer.getInt(8)!=CHANNEL_FLAG){
            return -1;
        }
//        System.out.println(footer.getInt(12));


        return footer.getInt(12);



    }

    public static void insertChannelId(RandomAccessFile apk, int adChannelId) {
        try {

            byte[] channelIdBuff = intToBytes2(adChannelId);
            int contentSize = channelIdBuff.length;

            //根据标识（0x06054b50）找到EOCD
            Pair<ByteBuffer, Long> eocdAndOffsetInFile = getEocd(apk);
            ByteBuffer eocd = eocdAndOffsetInFile.first;
            long eocdOffset = eocdAndOffsetInFile.second;

            if (ZipUtils.isZip64EndOfCentralDirectoryLocatorPresent(apk, eocdOffset)) {
                throw new SignatureNotFoundException("ZIP64 APK not supported");
            }
            int size = 8 + 4 + contentSize;
            long neweocdOffset = eocdOffset + size;

            //查找中央目录位移
            long centralDirOffset = getCentralDirOffset(eocd, eocdOffset);
            long newCentralDirOffset = centralDirOffset + size;

            //查找签名块位移
            Pair<ByteBuffer, Long> apkSigningBlockAndOffsetInFile = findApkSigningBlock(apk, centralDirOffset);
            long newSigningBlockSize = apkSigningBlockAndOffsetInFile.first.capacity() - 8 + size;


            //插入一组渠道 格式为[大小：标识：内容]
            int pos = (int) (apkSigningBlockAndOffsetInFile.second + 8);
            File tmp = File.createTempFile("tmp", null);//创建一个临时文件存放数据;
            FileInputStream fis = new FileInputStream(tmp);
            FileOutputStream fos = new FileOutputStream(tmp);
            apk.seek(pos);//把指针移动到指定位置
            byte[] buf = new byte[1024];
            int len = -1;
            //把指定位置之后的数据写入到临时文件
            while ((len = apk.read(buf)) != -1) {
                fos.write(buf, 0, len);
            }
            apk.seek(pos);//再把指针移动到指定位置，插入追加的数据
            ByteBuffer buffer = ByteBuffer.allocate(size);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putLong(size - 8);  //大小
            buffer.putInt(CHANNEL_FLAG); //标识
            buffer.putInt(adChannelId); //内容
            apk.write(buffer.array());
            //再把临时文件的数据写回
            while ((len = fis.read(buf)) > 0) {
                apk.write(buf, 0, len);
            }

            apk.seek(neweocdOffset + ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET);
            buffer = ByteBuffer.allocate(4);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.clear();
            buffer.putInt((int) newCentralDirOffset);
            apk.write(buffer.array());//修改eocd中央目录位移

            apk.seek(apkSigningBlockAndOffsetInFile.second);//移到签名块头
            buffer = ByteBuffer.allocate(8);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.clear();
            buffer.putLong(newSigningBlockSize);
            apk.write(buffer.array()); //修改签名头大小

            apk.seek(newCentralDirOffset - 24);
            buffer.clear();
            buffer.putLong(newSigningBlockSize);
            apk.write(buffer.array()); //修改签名尾大小

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static byte[] intToBytes2(int value) {
        byte[] src = new byte[4];
        src[0] = (byte) ((value >> 24) & 0xFF);
        src[1] = (byte) ((value >> 16) & 0xFF);
        src[2] = (byte) ((value >> 8) & 0xFF);
        src[3] = (byte) (value & 0xFF);
        return src;
    }

    public static int byteToInt(byte b) {
        return b & 0xFF;
    }

    public static int byteArrayToInt(byte[] b) {
        return   b[3] & 0xFF |
                (b[2] & 0xFF) << 8 |
                (b[1] & 0xFF) << 16 |
                (b[0] & 0xFF) << 24;
    }

}
