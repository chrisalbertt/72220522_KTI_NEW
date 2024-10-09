using System;
using System.ComponentModel.DataAnnotations;

namespace SampleSecureWeb.ViewModels;

public class RegistrationViewModel
{
    [Required]
    public string? Username { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [MinLength(12, ErrorMessage = "Password must be at least 12 characters long.")]
    [RegularExpression(@"^(?=.[a-z])(?=.[A-Z])(?=.*\d).+$", 
        ErrorMessage = "Password must contain at least one lowercase letter, one uppercase letter, and one digit.")]
    public string? Password { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [Display(Name = "Confirm Password")]
    [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
    public string? ConfirmPassword { get; set;}
}