(set-env!
 :source-paths   #{"src"}
 :resource-paths #{"resources"}
 :dependencies '[[org.clojure/clojure "1.9.0-alpha16"]
                 [org.shredzone.acme4j/acme4j-client "0.10"]
                 [org.shredzone.acme4j/acme4j-utils "0.10"]
                 [org.clojure/tools.logging "0.3.1"]
                 [ch.qos.logback/logback-classic "1.2.1"]
                 [environ "1.1.0"]
                 [boot-environ "1.1.0"]])

(require '[environ.boot :refer [environ]])

(deftask dev
  "Run a restartable system in the Repl"
  []
  (comp
   (environ :env {:keypair-path (str (System/getProperty "user.home") "/certificaat/keypair.pem")
                  :acme-server-uri "https://acme-staging.api.letsencrypt.org/directory"
                  :acme-uri "acme://letsencrypt.org/staging"
                  :acme-contact "mailto:daniel.szmulewicz@gmail.com"})
   (watch :verbose true)
   (notify :visual true)
   (repl :server true)))
