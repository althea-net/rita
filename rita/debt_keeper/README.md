# How DebtKeeper stores stuff
There are 3 different buckets which credits/debits to a neighboring node is stored:
- Incoming payments
- Debt buffer
- Debt
## Incoming payments
Incoming payments represents the payments which a node as recieved from its neighbours. It is
treated differently from credit from traffic counters as _it will never be sent back to the node
which sent it_.
## Debt buffer
Debt buffer represents a \"time delayed\" view of the debts which another node owes us, enabling
small delays in payments caused by misaligned billing cycles or occasional missed payments to
not close a connection
## Debt
Debt represents the amount of stuff we owe others or others owe us _at this moment, taking into
account the debt buffering effects_
# How DebtKeeper works
There are 3 different ways to update the DebtKeeper state:
- PaymentReceived
- TrafficUpdate
- CycleUpdate
## PaymentRecieved
This simply increments the incoming payments value
## TrafficUpdate
Traffic updates are treated differently depending on if the update is positive or negative.
If the update is positive (we pay them), we apply the credit immediately by adding the amount
to the Debt value
If the update is negative (they pay us), we buffer the debit to give them time to pay it back,
by adding the update to the value on the back of the Debt buffer.
## CycleUpdate
Cycle updates does two things, updating the state of which the debt is stored and also producing
a DebtAction based on the result of the update
### State update
To update the state, first we pop off the front value of the debt buffer to get a \"time delayed\"
debt value from several billing cycles ago. 
Then we check if the PaymentRecieved is enough to pay off the time delayed debt. If there is
enough, we can also check if there is any Debt to pay off, and try to pay that off with the 
payments we recieved.
However, if the PaymentRecieved value is not enough to pay off the time delayed debt, we just
subtract the difference from the debt.
### DebtAction decision
- If their debt is below our cutoff, suspend the tunnel
- If their debt was below our cutoff, and is now above, reopen the tunnel
- If their debt is above our payment threshold, pay them
- Else, nothing needs to be done"