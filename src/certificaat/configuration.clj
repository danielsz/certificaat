(ns certificaat.configuration
  (:require [clojure.java.io :as io]
            [certificaat.account :as account]
            [environ.core :refer [env]]))

(defn create []
  (let [config-dir (io/file (:certificaat-config-dir env))
        keypair-file (io/file (str (:certificaat-config-dir env) (:certificaat-keypair-filename env)))
        domain-keypair-file (io/file (str (:certificaat-config-dir env) (:certificaat-domain-keypair-filename env)))]
    (when (not (.isDirectory config-dir))
      (.mkdir config-dir))
    (when (not (.exists keypair-file))
      (account/persist))
    (when (not (.exists domain-keypair-file))
      (account/persist (account/keypair) (str (:certificaat-config-dir env) (:certificaat-domain-keypair-filename env))))))
