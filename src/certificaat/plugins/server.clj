(ns certificaat.plugins.server
  (:require
   [certificaat.acme4j.session :as session]
   [certificaat.acme4j.keypair :as keypair]
   [certificaat.acme4j.account :as account]
   [certificaat.acme4j.order :as order]
   [certificaat.kung-fu :as k]
   [immutant.web :refer [run stop]]
   [clojure.string :as str]
   [clojure.java.io :as io]
   [clojure.tools.logging :as log]))

(def stop-server stop )

(defn handler [challenges]
  (fn [request]
    (loop [xs challenges]
      (if (= (:uri request) (str "/.well-known/acme-challenge/" (.getToken (first xs))))
        (log/spyf "OK %s" {:status 200
                           :headers {"Content-Type" "text/plain"}
                           :body (.getAuthorization (first xs))})
        (recur (rest xs))))))

(defn start-server [handler port]
  (let [server (run handler {:port port})]
    server))

(defn listen
  ([options]
   (let [challenges (k/get-challenges options)]
     (listen challenges options)))
  ([challenges {{{port :port enabled :enabled} :httpd} :plugins :as options}]
              (when enabled
                (let [handler (handler challenges)]
                  (start-server handler port)))))




