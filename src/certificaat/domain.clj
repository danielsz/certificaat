(ns certificaat.domain
  (:require [clojure.spec.alpha :as s]))

(defn validate [spec val]
  (let [v (s/conform spec val)]
    (if (= v ::s/invalid)
      (throw (ex-info "Invalid input" (s/explain-data spec val)))
      v)))

(s/def ::config-dir string?)
(s/def ::key-size #{1024 2048 4096})
(s/def ::key-type #{:rsa :ec})
(s/def ::certificaat-setup (s/keys :req-un [::config-dir ::key-size ::key-type]))
