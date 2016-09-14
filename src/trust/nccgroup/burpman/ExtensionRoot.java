package trust.nccgroup.burpman;

import burp.*;

import java.util.Arrays;

public class ExtensionRoot implements IBurpExtender {

  private IBurpExtenderCallbacks callbacks;
  private IExtensionHelpers helpers;



  public void registerExtenderCallbacks(IBurpExtenderCallbacks _callbacks) {

    callbacks = _callbacks;
    helpers = callbacks.getHelpers();

    callbacks.setExtensionName("Burpman");

    PairedTabAssemblyLine ptal = null;
    try {
      ptal = new PairedTabAssemblyLine(callbacks,
        new ScriptTab.Factory(
          "Pre-request Script",
          ComponentSynchronizer.State.class.getField("preRequestEditor"),
          callbacks
        ),
        new ScriptTab.Factory(
          "Tests",
          ComponentSynchronizer.State.class.getField("testsEditor"),
          callbacks
        ),
        new ResultsTab.Factory("Tests", callbacks)
      );
    } catch (Throwable t) {
      t.printStackTrace();
      return;
    }

    PairedTabAssemblyLine _ptal = ptal;
    Arrays.stream(_ptal.factories).forEach((f)->{
      callbacks.registerMessageEditorTabFactory(_ptal);
    });

    callbacks.registerHttpListener(new PostmanInterceptor(callbacks));

  }


}

