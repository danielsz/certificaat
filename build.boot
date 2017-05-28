(set-env!
 :source-paths   #{"src"}
 :resource-paths #{"resources"}
 :dependencies '[[adzerk/boot-jar2bin "1.1.0" :scope "test"]
                 [org.clojure/clojure "1.9.0-alpha17"]
                 [org.clojure/core.async "0.3.442"]
                 [org.danielsz/lang-utils "0.1.0-SNAPSHOT"]
                 [org.shredzone.acme4j/acme4j-client "0.10"]
                 [org.shredzone.acme4j/acme4j-utils "0.10"]
                 [org.clojure/tools.logging "0.3.1"]
                 [ch.qos.logback/logback-classic "1.2.3"]
                 [org.clojure/tools.cli "0.3.5"]
                 [org.kohsuke/libpam4j "1.8"]
                 [mvxcvi/puget "1.0.1"]
                 [me.raynes/conch "0.8.0"]
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
   (environ :env {:certificaat-config-dir (str (System/getProperty "user.home") "/.config/certificaat/")
                  :certificaat-keypair-filename "keypair.pem"
                  :certificaat-domain-keypair-filename "teamsocial.pem"
                  :certificaat-acme-server-uri "https://acme-staging.api.letsencrypt.org/directory"
                  :certificaat-acme-uri "acme://letsencrypt.org/staging"
                  :certificaat-acme-contact "mailto:daniel.szmulewicz@gmail.com"
                  :certificaat-domain "teamsocial.me"
                  :certificaat-organization "sapiens sapiens"
                  :certificaat-challenge-type "dns-01"})
   (watch :verbose true)
   (notify :visual true)
   (repl :server true)))

(def +project+ "certificaat")
(def +version+ "1.0.0")

(deftask build
  "Builds an uberjar of this project that can be run with java -jar"
  []
  (comp
   (aot :namespace '#{certificaat.core})
   (pom :project (symbol +project+)
        :version +version+)
   (uber)
   (jar :main 'certificaat.core :file (str +project+ "-" +version+ ".jar"))
   (bin :output-dir "bin")))


