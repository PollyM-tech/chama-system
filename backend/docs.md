## Multitenant chama system
Treat User as platform identity and Membership as chama-specific access.
Stop using User.role for chama authorization.
Use Membership.role for all chama-level permissions.
Add strict membership checks on every chama-based endpoint.
Restrict member onboarding and access sending to admin, treasurer, and secretary.
Do not give exclusive full control to chairperson.
Add a My Chamas endpoint for logged-in users.
Add a User Memberships endpoint to see all chamas a user belongs to.
Separate soft delete from permanent deactivation.
Add recoverable delete flow for admin backend.
Add irreversible deactivate flow for final shutdown.
Add deleted/deactivated fields to User model.
Keep account status separate from membership status.
Block authenticated users from accessing chamas they do not belong to.
Audit all sensitive user and membership actions.
Standardize helper methods for permission checks.
Move toward invite-controlled onboarding rather than unrestricted access to all chamas.
Make frontend choose current chama context from the user’s memberships.

# design notes
Do not use User.role anymore for chama permissions.
Do not let authenticated users browse all chamas blindly.
Always scope chama data by chama_id and active membership.
A deleted user can be restored; a deactivated user should not be restored.
Membership removal is not the same as account deletion.
Chairperson should not automatically have all powers unless you deliberately add that policy.

# models.py 
User = platform identity only
Membership = chama-specific role and permissions
User.role is removed from chama authorization
soft delete and permanent deactivation are separated
user account status is separate from membership status
onboarding can be invite-controlled
sensitive actions can be audited
helper methods are standardized for permission checks

#loans
non-finance users only see their own loans
non-finance users cannot view another borrower’s loan detail
repayments are blocked before disbursement
approval works
disbursement works
repayment works after disbursement
loan status can move to partially_repaid
rejection cleanup was added in code