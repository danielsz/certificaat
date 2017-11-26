(set-env!
 :source-paths   #{"src"}
 :resource-paths #{"src" "resources"}
 :dependencies '[[adzerk/boot-jar2bin "1.1.0" :scope "test"]
                 [org.clojure/test.check "0.10.0-alpha2" :scope "test"]
                 [org.clojure/clojure "1.9.0-RC1"]
                 [org.clojure/core.async "0.3.442"]
                 [org.danielsz/lang-utils "0.1.0-SNAPSHOT"]
                 [org.shredzone.acme4j/acme4j-client "0.13"]
                 [org.shredzone.acme4j/acme4j-utils "0.13"]
                 [org.clojure/tools.logging "0.3.1"]
                 [ch.qos.logback/logback-classic "1.2.3"]
                 [org.clojure/tools.cli "0.3.5"]
                 [org.kohsuke/libpam4j "1.8"]
                 [mvxcvi/puget "1.0.1"]
                 [me.raynes/conch "0.8.0"]
                 [com.draines/postal "2.0.2"]
                 [clj-http "3.6.0"]
                 [ring "1.6.1"]
                 [environ "1.1.0"]
                 [boot-environ "1.1.0"]])

(require '[environ.boot :refer [environ]]
         '[adzerk.boot-jar2bin :refer [bin]])

(deftask dev
  "Run a restartable system in the Repl"
  []
  (comp
   (watch :verbose true)
   (notify :visual true)
   (repl :server true)))

(def +version+ "2.0.0")
(task-options!
 push {:repo-map {:url "https://clojars.org/repo/"}}
 pom {:project 'org.danielsz/certificaat
      :version +version+
      :scm {:name "git"
            :url "https://github.com/danielsz/certificaat"}}
 aot {:namespace '#{certificaat.core}}
 bin {:output-dir "bin"}
 jar {:main 'certificaat.core :file (str "certificaat-" +version+ ".jar")})

(deftask build-local
  []
  (comp (pom) (jar) (install)))

(deftask build-uberjar
  "Builds an uberjar of this project that can be run with java -jar"
  []
  (comp
   (aot)
   (pom)
   (uber)
   (jar)))

(deftask build-binary
  []
  (comp (build-uberjar) (bin)))

(deftask build-uberjar-persist
  []
  (comp (build-uberjar)
        (sift :include #{(re-pattern (str "certificaat-" +version+ ".jar"))})
        (target :dir #{"bin"})))

(deftask push-release
  []
  (comp
   (pom) (jar) (push)))
