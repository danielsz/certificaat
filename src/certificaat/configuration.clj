(ns certificaat.configuration
  (:require [clojure.java.io :as io]
            [certificaat.account :as account]
            [environ.core :refer [env]]))

(defn create-config-dir [config-dir]
  (let [config-dir (io/file config-dir)]
    (when (not (.isDirectory config-dir))
      (.mkdir config-dir))))

(defn add-keypair [config-dir keypair-filename keypair]
  (let [keypair-file (io/file (str config-dir keypair-filename))]
    (when (not (.exists keypair-file))
      (account/persist keypair (str config-dir keypair-filename)))))
