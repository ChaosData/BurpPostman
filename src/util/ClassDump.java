package util;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class ClassDump {

  public static void dump(Class<?> _class) {
    System.out.println("Name: " + _class.getCanonicalName());
    System.out.println("Methods:");
    for (Method m : _class.getDeclaredMethods()) {
      System.out.println("  " + m.toGenericString());
    }

    System.out.println("Fields:");
    for (Field f : _class.getDeclaredFields()) {
      System.out.println("  " + f.toGenericString());
    }

  }

}
