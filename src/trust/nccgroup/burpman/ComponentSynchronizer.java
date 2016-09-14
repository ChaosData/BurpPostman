package trust.nccgroup.burpman;

import burp.IExtensionHelpers;
import burp.IRequestInfo;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;
import org.fife.ui.rsyntaxtextarea.TextEditorPane;
import util.Ref;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

public class ComponentSynchronizer {

  public static final AtomicLong id_counter = new AtomicLong(((long)new SecureRandom().nextInt(Integer.MAX_VALUE)) * 10000);
  public static final Map<Long, State> tabState = new ConcurrentHashMap<>();


  public static final String HEADER = "x-burpman: ";


  public static class State {
    public TextEditorPane preRequestEditor = null;
    public TextEditorPane testsEditor = null;
    //public String preRequestScript = null;
    //public String testsScript = null;
    public Map<String, Boolean> tests = Maps.newHashMap(ImmutableMap.of("Lol", true, "YOLO", false)); //new HashMap<>();
  }

  public static synchronized
  long getRequestId(IExtensionHelpers helpers, Ref<byte[]> currentMessage) {
    IRequestInfo iri = helpers.analyzeRequest(currentMessage.value);

    for (String h : iri.getHeaders()) {
      String hl = h.toLowerCase();
      if (hl.startsWith(HEADER)) {
        return Long.parseLong(hl.substring(HEADER.length()));
      }
    }
    return -1;
  }

  public static synchronized
  void setRequestId(IExtensionHelpers helpers, Ref<byte[]> currentMessage, long id) {
    IRequestInfo iri = helpers.analyzeRequest(currentMessage.value);

    Ref<Boolean> found = Ref.wrap(false);
    List<String> nheaders = iri.getHeaders().stream().map((String h) -> {
      if (h.startsWith(HEADER)) {
        found.value = true;
        return HEADER + id;
      }
      return h;
    }).collect(Collectors.toList());
    if (!found.value) {
      nheaders.add(HEADER + id);
    }

    byte[] nbody = Arrays.copyOfRange(currentMessage.value, iri.getBodyOffset(), currentMessage.value.length);

    currentMessage.value = helpers.buildHttpMessage(nheaders, nbody);
  }


  public static synchronized
  long synchronizeRequest(IExtensionHelpers helpers, Ref<byte[]> currentMessage) {
    IRequestInfo iri = helpers.analyzeRequest(currentMessage.value);

    for (String h : iri.getHeaders()) {
      String hl = h.toLowerCase();
      if (hl.startsWith(HEADER)) {
        return Long.parseLong(hl.substring(HEADER.length()));
      }
    }
    long id = id_counter.incrementAndGet();
    byte[] nbody = Arrays.copyOfRange(currentMessage.value, iri.getBodyOffset(), currentMessage.value.length);
    List<String> nheaders = new ArrayList<>(iri.getHeaders());
    nheaders.add(HEADER + id);
    currentMessage.value = helpers.buildHttpMessage(nheaders, nbody);
    return id;
  }

  public static synchronized
  long resynchronizeRequest(IExtensionHelpers helpers, Ref<byte[]> currentMessage) {
    long id = id_counter.incrementAndGet();

    final Ref<Boolean> found = Ref.wrap(false);
    IRequestInfo iri = helpers.analyzeRequest(currentMessage.value);
    List<String> nheaders = iri.getHeaders().stream().map((String hl) -> {
      if (hl.startsWith(HEADER)) {
        found.value = true;
        return hl.substring(0, HEADER.length()) + id;
      }
      return hl;
    }).collect(Collectors.toList());
    if (!found.value) {
      nheaders.add(HEADER + id);
    }

    byte[] nbody = Arrays.copyOfRange(currentMessage.value, iri.getBodyOffset(), currentMessage.value.length);
    currentMessage.value = helpers.buildHttpMessage(nheaders, nbody);
    return id;
  }


  public static synchronized
  State getState(long id) {
    tabState.putIfAbsent(id, new State());
    return tabState.get(id);
  }


}
