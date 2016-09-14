package trust.nccgroup.burpman;

import burp.*;

import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicLong;

public class PairedTabAssemblyLine implements IMessageEditorTabFactory {
  //note: this relies on burp making the generation calls based on order of registration

  public static final AtomicLong pair_id_counter =
    new AtomicLong(((long)new SecureRandom().nextInt(Integer.MAX_VALUE)) * 10000);

  private IBurpExtenderCallbacks callbacks;
  private IExtensionHelpers helpers;


  public PairedMessageEditorTabFactory[] factories;
  private int state = 0;
  private long current_pair_id = pair_id_counter.incrementAndGet();
  //private Object[] tabs = null;


  public PairedTabAssemblyLine(IBurpExtenderCallbacks _callbacks, PairedMessageEditorTabFactory... _factories) {
    callbacks = _callbacks;
    helpers = callbacks.getHelpers();
    factories = _factories;
    //tabs = new Object[factories.length];
  }

  @Override
  public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {

    IMessageEditorTab tab = factories[state % factories.length].createNewInstance(controller, editable, current_pair_id);
    //tabs[state] = tab;

    state += 1;
    if (state == factories.length*2) {
      state = 0;
      if (tab != null) {
        current_pair_id = pair_id_counter.incrementAndGet();
      }
    }

    return tab;
  }
}
