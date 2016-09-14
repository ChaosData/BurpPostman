package trust.nccgroup.burpman;

import burp.IMessageEditorController;

public interface PairedMessageEditorTabFactory {

  PairedMessageEditorTab createNewInstance(IMessageEditorController controller,
                                           boolean editable, long pair_id);

}
