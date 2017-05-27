(ns certificaat.util.download
  (:require [clj-http.client :as client]
            [clojure.tools.logging :as log]))

(defn download [url]
  (log/info "Downloading" url)
  (let [resp (client/get url {:as :byte-array :throw-exceptions false})]
    (when (= (:status resp) 200)
      (:body resp))))


