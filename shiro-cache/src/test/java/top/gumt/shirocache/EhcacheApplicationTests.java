package top.gumt.shirocache;

import org.junit.Test;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Properties;

public class EhcacheApplicationTests {
    @Test
    public void test() {
        Properties properties = System.getProperties();
        //遍历所有的属性
        properties.stringPropertyNames();
        for (String key : properties.stringPropertyNames()) {
            //输出对应的键和值
            System.out.println(key + "=" + properties.getProperty(key));
        }

    }
}
