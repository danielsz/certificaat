(ns certificaat.plugins.server
  (:require
   [certificaat.acme4j.session :as session]
   [certificaat.acme4j.keypair :as keypair]
   [certificaat.acme4j.account :as account]
   [certificaat.acme4j.challenge :as challenge]
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

(defn get-challenges [{:keys [domain config-dir acme-uri keypair-filename] :as options}]
  (let [session (session/create acme-uri)
        keypair (keypair/read config-dir keypair-filename)
        login (account/login (str config-dir "account.url") keypair session)
        paths (filter (comp #(= (first %) "challenge") #(str/split % #"\.") #(.getName %)) (file-seq (io/file (str config-dir domain))))]
    (for [path paths
          :let [challenge (challenge/restore login path)]]
      challenge)))

(defn listen
  ([options]
   (let [challenges (get-challenges options)]
     (listen challenges options)))
  ([challenges {{{port :port enabled :enabled} :httpd} :plugins :as options}]
              (when enabled
                (let [handler (handler challenges)]
                  (start-server handler port)))))




