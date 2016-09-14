package trust.nccgroup.burpman;

import burp.*;
import org.fife.ui.rsyntaxtextarea.*;
import org.fife.ui.rtextarea.*;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.io.IOException;
import java.lang.reflect.Field;

import trust.nccgroup.burpman.ComponentSynchronizer.State;
import util.Ref;

class ScriptTab extends PairedMessageEditorTab {

  public static class Factory implements PairedMessageEditorTabFactory {
    private String caption = null;
    private Field stateField = null;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;


    public Factory(String _caption, Field _stateField, IBurpExtenderCallbacks _callbacks) {
      caption = _caption;
      stateField = _stateField;
      callbacks = _callbacks;
      helpers = callbacks.getHelpers();

    }

    @Override
    public PairedMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable, long pair_id) {
      if (controller == null) {
        return null;
      }

      return new ScriptTab(caption, stateField, pair_id, controller, editable, callbacks);
    }
  }

  private IBurpExtenderCallbacks callbacks;
  private IExtensionHelpers helpers;
  //public long id = -1;
  private long pair_id = -1;

  private IMessageEditorController controller;
  private boolean editable;
  private RTextScrollPane editor_pane;
  private TextEditorPane editor;

  private byte[] currentMessage;
  private byte type = 0;

  private String caption = null;
  private Field stateField = null;
  private boolean initialized = false;

  public ScriptTab(String _caption, Field _stateField, long _pair_id,
                   IMessageEditorController _controller, boolean _editable,
                   IBurpExtenderCallbacks _callbacks) {


    if (_controller == null) {
      return;
    }

    caption = _caption;
    stateField = _stateField;
    pair_id = _pair_id;

    callbacks = _callbacks;
    helpers = callbacks.getHelpers();

    controller = _controller;
    editable = _editable;


    if (!editable) {
      return;
    }

    //note: this is needed to fix a weird bug w/ burp causing key events to drop
    UIManager.put("RTextAreaUI.actionMap", null);
    UIManager.put("RSyntaxTextAreaUI.actionMap", null);
    JTextComponent.removeKeymap("RTextAreaKeymap");


    editor = new TextEditorPane(RTextArea.INSERT_MODE, true);
    editor.setCodeFoldingEnabled(false);
    editor_pane = new RTextScrollPane(editor, true);


    editor.setFont(new Font("DejaVu Sans Mono", editor.getFont().getStyle(), 12));
    Theme theme = null;
    try {
      theme = Theme.load(getClass().getResourceAsStream("/org/fife/ui/rsyntaxtextarea/themes/dark.xml"));
      theme.apply(editor);
    } catch (IOException e) {
      e.printStackTrace();
    }

    editor.setEditable(_editable);
    callbacks.customizeUiComponent(editor);
    callbacks.customizeUiComponent(editor_pane);
    editor.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);

  }


  @Override
  public String getTabCaption() {
    return caption;
  }

  @Override
  public Component getUiComponent() {
    return editor_pane;
  }

  @Override
  public boolean isEnabled(byte[] content, boolean isRequest) {
    return editable && isRequest;
  }

  @Override
  public void setMessage(byte[] content, boolean isRequest) {

    if (!initialized) {
      Ref<byte[]> msgref = Ref.wrap(content);
      ComponentSynchronizer.setRequestId(helpers, msgref, pair_id);
      State state = ComponentSynchronizer.getState(pair_id);
      try {
        stateField.set(state, editor);
      } catch (Throwable t) { t.printStackTrace(); }

      /*
      Ref<byte[]> msgref = Ref.wrap(content);
      long reqid = ComponentSynchronizer.getRequestId(helpers, msgref);

      if (reqid == -1) { //clean
        id = ComponentSynchronizer.resynchronizeRequest(helpers, msgref);
        State state = ComponentSynchronizer.getState(id);
        try {
          stateField.set(state, editor);
        } catch (Throwable t) { t.printStackTrace(); }
      } else { //already set in request
        State state = ComponentSynchronizer.getState(reqid);
        Object stateEditor = null;
        try {
          stateEditor = stateField.get(state);
          if (stateEditor == null) { //clean, was set by another tab
            stateField.set(state, editor);
            id = reqid;
          } else if (stateEditor != editor) { //unclean, this request came from somewhere else
            id = ComponentSynchronizer.resynchronizeRequest(helpers, msgref);
            state = ComponentSynchronizer.getState(id);
            try {
              stateField.set(state, editor);
            } catch (Throwable t) { t.printStackTrace(); }
          }
        } catch (Throwable t) { t.printStackTrace(); }
      }
      */
      currentMessage = msgref.value;
      initialized = true;
    } else {
      currentMessage = content;
    }
  }

  @Override
  public byte[] getMessage() {
    return currentMessage;
  }

  @Override
  public boolean isModified() {
    if (editor.isDirty()) {
//      State state = ComponentSynchronizer.getState(id);
//      try {
        //stateField.set(state, editor.getText());
//        stateField.set(state, editor);
//      } catch (Throwable t) { t.printStackTrace(); }
      return true;
    }
    return false;
  }

  @Override
  public byte[] getSelectedData() {
    return editor.getSelectedText().getBytes();
  }
}


