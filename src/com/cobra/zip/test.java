package com.cobra.zip;

import java.io.File;
import java.io.RandomAccessFile;

public class test {

    public static void main(String[] arg) throws Exception{


        System.out.println(0x12345678);

        RandomAccessFile file=new RandomAccessFile("apk/app-release.apk","rw");

        ZipHelper.insertChannelId(file,5555);



       int channel= ZipHelper.readChannel(file);
       System.out.println(channel);
    }
}
