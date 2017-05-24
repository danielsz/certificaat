(ns certificaat.util.configuration
  (:require [clojure.java.io :as io]
            [certificaat.acme4j.account :as account]
            [environ.core :refer [env]]))

(defn create-dir [dir]
  (let [dir (io/file dir)]
    (when (not (.isDirectory dir))
      (.mkdir dir))))

(defn add-keypair [config-dir keypair-filename keypair]
  (let [keypair-file (io/file (str config-dir keypair-filename))]
    (when (not (.exists keypair-file))
      (account/persist keypair (str config-dir keypair-filename)))))
