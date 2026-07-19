namespace EclipsVault.Core.Application.Abac;

/// <summary>
/// An <see cref="IAbacResource"/> a grant can be issued against — a stored secret, in whichever
/// shape it is being looked at (list row or detail view).
///
/// A dynamic-secret role is deliberately not one: there is nothing to share about a role whose
/// whole point is that anyone entitled to it mints their own credential.
///
/// This is a marker rather than a type list at the one place that consults grants, because getting
/// it wrong is silent — a stored secret the handler forgets to look up grants for simply becomes
/// invisible to the person it was shared with, with nothing failing to say so.
/// </summary>
public interface IGrantableResource : IAbacResource;
