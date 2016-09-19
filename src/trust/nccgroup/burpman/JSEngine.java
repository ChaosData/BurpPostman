package trust.nccgroup.burpman;


import com.google.common.base.Charsets;
import com.google.common.collect.Lists;
import com.google.common.io.CharStreams;
import org.ringojs.engine.RhinoEngine;
import org.ringojs.engine.RingoConfig;
import org.ringojs.engine.RingoWrapFactory;
import org.ringojs.repository.FileRepository;
import org.ringojs.repository.Repository;
import org.ringojs.repository.StringResource;
import org.ringojs.repository.ZipRepository;
import org.ringojs.util.StringUtils;

import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class JSEngine {

  @FunctionalInterface
  public interface Proc {
    void run();
  }


  private static RingoConfig config;
  private static RhinoEngine engine;


  //private static List<String> userModules = new ArrayList<>();


  public static synchronized RhinoEngine getInstance(String pluginpath) {
    if (engine != null) {
      return engine;
    }

    try {
      Repository home = new ZipRepository(pluginpath);

      String[] systemModulePath = {"modules", "packages"};
      String[] userModulePath = {"./node_modules"};

      RingoConfig _config = new RingoConfig(home, userModulePath, systemModulePath);

      _config.setWrapFactory(new RingoWrapFactory());
      _config.setOptLevel(9);
      _config.setDebug(false);
      _config.setVerbose(true);
      _config.setStrictVars(true);
      _config.setCharset("UTF-8");

      engine = new RhinoEngine(_config, null);
      config = _config;
      init(engine);
    } catch (Throwable t) {
      t.printStackTrace();
    }

    return engine;
  }

  public static void init(RhinoEngine _engine) {
    try {
      InputStream is = JSEngine.class.getResource("/preload.js").openStream();
      String preloadjs = CharStreams.toString(new InputStreamReader(is, Charsets.UTF_8));
      _engine.runScript(new StringResource("preload", preloadjs));
    } catch (Throwable t) {
      t.printStackTrace();
    }
  }
}
