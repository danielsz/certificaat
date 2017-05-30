(ns certificaat.util.configuration
  (:require [clojure.java.io :as io]
            [certificaat.acme4j.account :as account]
            [certificaat.util.download :as d]
            [environ.core :refer [env]]
            [clojure.string :as str]))

(def config-dir #(or (System/getenv "XDG_CONFIG_HOME") (str (System/getProperty "user.home") "/.config/certificaat/")))

(defn add-keypair [config-dir keypair-filename keypair]
  (let [keypair-file (io/file (str config-dir keypair-filename))]
    (when (not (.exists keypair-file))
      (io/make-parents keypair-file)
      (account/persist keypair (str config-dir keypair-filename)))))

(defn save-agreement [config-dir reg]
  (let [url (.getAgreement reg)
        agreement (d/download (str url))
        filename (last (str/split (.getPath url) #"/"))]
    (with-open [w (io/output-stream (str config-dir filename))]
      (.write w agreement))))
