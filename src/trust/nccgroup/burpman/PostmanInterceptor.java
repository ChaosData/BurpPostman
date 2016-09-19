package trust.nccgroup.burpman;

import burp.*;
import org.ringojs.engine.RhinoEngine;

import static trust.nccgroup.burpman.ComponentSynchronizer.HEADER;

public class PostmanInterceptor implements IHttpListener {

  private IBurpExtenderCallbacks callbacks;
  private IExtensionHelpers helpers;


  public PostmanInterceptor(IBurpExtenderCallbacks _callbacks) {
    callbacks = _callbacks;
    helpers = callbacks.getHelpers();
  }

  @Override
  public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
    if (toolFlag != IBurpExtenderCallbacks.TOOL_REPEATER) {
      return;
    }


    long id = -1;
    IRequestInfo iri = helpers.analyzeRequest(messageInfo.getRequest());
    for (String h : iri.getHeaders()) {
      String hl = h.toLowerCase();
      if (hl.startsWith(HEADER)) {
        id = Long.parseLong(hl.substring(HEADER.length()));
        break;
      }
    }

    if (id == -1) {
      return;
    }

    ComponentSynchronizer.State state = ComponentSynchronizer.getState(id);

    RhinoEngine engine = JSEngine.getInstance(callbacks.getExtensionFilename());

    String script = null;
    if (messageIsRequest && state.preRequestEditor != null) {
      script = state.preRequestEditor.getText();
    } else if (!messageIsRequest && state.testsEditor != null) {
      script = state.testsEditor.getText();
    }

    if (script == null) {
      return;
    }
    //ScriptableObject so = null;
    try {
      /*Object o = */engine.evaluateExpression(script);
      //if (o instanceof ScriptableObject) {
      //  so = (ScriptableObject)o;
      //}
    } catch (Throwable t) {
      t.printStackTrace();
    }


//    try {
//      Object o = engine.evaluateExpression("" +
//        "function lol(m, f) { console.log(ByteArray.wrap(m.get('name')).decodeToString('ASCII')); f.run(); java.lang.System.out.println('FFF') }; var x = 'zzz'; yolo(); this\n"
//      );
//
//      engine.invoke(o, "lol", Maps.newHashMap(ImmutableMap.of("name", new byte[]{(byte) 0xff})), (JSEngine.Proc) () -> {
//        System.out.println("aa");
//      });
//      if (o instanceof ScriptableObject) {
//        ScriptableObject so = (ScriptableObject) o;
//        System.out.println(so.get("x"));
//      }
//    } catch (Throwable t) {
//      t.printStackTrace();
//    }


//      System.out.println("preRequest: " + state.preRequestEditor.getText());
//      System.out.println("tests: " + state.testsEditor.getText());

  }
}
