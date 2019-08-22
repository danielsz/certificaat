(ns certificaat.acme4j.order)

(defn create [account]
  (let [order-builder (.newOrder account)]
    (.create order-builder)))
