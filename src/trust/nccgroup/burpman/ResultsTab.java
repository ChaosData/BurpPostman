package trust.nccgroup.burpman;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorController;
import com.google.common.base.Charsets;
import com.google.common.html.HtmlEscapers;
import com.google.common.io.CharStreams;
import org.fit.cssbox.swingbox.BrowserPane;

import java.awt.*;
import java.io.*;
import java.lang.reflect.Field;
import java.net.URLEncoder;


class ResultsTab extends PairedMessageEditorTab {

  private static String TEMPLATE = null;
  private static final String REPLACE_TOKEN = "{{replace}}\n";
  static {
    try {
      InputStream is = ResultsTab.class.getResource("/tests.html").openStream();
      TEMPLATE = CharStreams.toString(new InputStreamReader(is, Charsets.UTF_8));
    } catch (Throwable t) {
      t.printStackTrace();
      TEMPLATE = "";
    }
  }

  public static class Factory implements PairedMessageEditorTabFactory {
    private String caption = null;
    private Field stateField = null;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;


    public Factory(String _caption, IBurpExtenderCallbacks _callbacks) {
      caption = _caption;
      callbacks = _callbacks;
      helpers = callbacks.getHelpers();
    }

    @Override
    public PairedMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable, long pair_id) {
      if (controller == null) {
        return null;
      }

      return new ResultsTab(caption, pair_id, controller, editable, callbacks);
    }
  }

  private String createTestResult(String name, boolean pass) {
    String pf = (pass ? "pass" : "fail");
    return
      "      <div class=\"response-test-item\">\n" +
      "        <span class=\"response-test-status " + pf + "\">" + pf + "</span>\n" +
      "        <span class=\"response-test-text\">" + HtmlEscapers.htmlEscaper().escape(name) + "</span>\n" +
      "      </div>\n";
  }

  private IBurpExtenderCallbacks callbacks;
  private IExtensionHelpers helpers;
  private long pair_id = -1;

  private IMessageEditorController controller;
  private boolean editable;
  private byte[] currentMessage;

  private String caption = null;

  private BrowserPane pane = null;

  public ResultsTab(String _caption, long _pair_id,
                   IMessageEditorController _controller, boolean _editable,
                   IBurpExtenderCallbacks _callbacks) {

    if (_controller == null) {
      System.out.println("NULL!!");
      return;
    }

    caption = _caption;
    pair_id = _pair_id;

    callbacks = _callbacks;
    helpers = callbacks.getHelpers();

    controller = _controller;
    editable = _editable;

    if (editable) {
      return;
    }

    pane = new BrowserPane();
  }


  @Override
  public String getTabCaption() {
    return caption;
  }

  @Override
  public Component getUiComponent() {
    return pane;
  }

  @Override
  public boolean isEnabled(byte[] content, boolean isRequest) {
    return !editable && !isRequest;
  }

  @Override
  public void setMessage(byte[] content, boolean isRequest) {


    StringBuilder results = new StringBuilder();
    ComponentSynchronizer.State state = ComponentSynchronizer.getState(pair_id);
    state.tests.forEach((String name, Boolean pass)->{
      results.append(createTestResult(name, pass));
    });

    String html = TEMPLATE.replace(REPLACE_TOKEN, results.toString());

    PrintStream original = System.out;
    try {
      String data = URLEncoder.encode(html, "UTF-8");
      System.setOut(new PrintStream(new ByteArrayOutputStream() {
        @Override
        public void write(int b) { }

        @Override
        public void write(byte[] b, int off, int len) { }

        @Override
        public void writeTo(OutputStream out) throws IOException { }
      }));

      pane.setText(data);
    } catch (Throwable t) {
      t.printStackTrace();
    }
    finally {
      System.setOut(original);

    }

    currentMessage = content;
  }

  @Override
  public byte[] getMessage() {
    return currentMessage;
  }

  @Override
  public boolean isModified() {
    return true;
  }

  @Override
  public byte[] getSelectedData() {
    return pane.getSelectedText().getBytes();
  }
}


