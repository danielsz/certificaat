(ns certificaat.acme4j.order)

(defn create [account]
  (doto (.newOrder account)
    (.create)))
