package util;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.*;

public class ComponentDump {

  public static void dump(Container c) {
    dump(c, 0);
  }

  public static void dump(Container _c, int depth) {
    Component[] cs = _c.getComponents();
    for (Component c : cs) {
      System.out.println(c.getName());
      System.out.println(c.getClass());
      System.out.println(c);
      if (c instanceof JTextComponent) {
        JTextComponent jtc = (JTextComponent)c;
        System.out.println("JTextComponent.getText(): " + jtc.getText());
      }
      if (c instanceof JLabel) {
        JLabel jl = (JLabel) c;
        System.out.println("JLabel.getText(): " + jl.getText());
      }

      new PrintClassHierarchy(c.getClass()).printHierarchy();
      if (c instanceof Container) {
        dump((Container)c, depth + 1);
      }
      System.out.println("-----");
    }
    System.out.println("=====");
  }
}
