(ns certificaat.plugins.copy-to-path
  (:require [clojure.java.io :as io]))

(defn copy [{{{path :path enabled :enabled} :copy-to-path} :plugins domain :domain config-dir :config-dir :as options}]
  (when enabled
    (let [source (str config-dir domain "/")
          cert-file (str source "cert-chain.crt")]
      (when (.isDirectory (io/file path))
        (io/copy (io/file cert-file) (io/file (str path "/cert-chain.crt")))))))
