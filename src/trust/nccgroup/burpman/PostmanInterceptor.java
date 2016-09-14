package trust.nccgroup.burpman;

import burp.*;

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

    if (id != -1) {
      ComponentSynchronizer.State state = ComponentSynchronizer.getState(id);
      System.out.println("preRequest: " + state.preRequestEditor.getText());
      System.out.println("tests: " + state.testsEditor.getText());
    }

  }
}
